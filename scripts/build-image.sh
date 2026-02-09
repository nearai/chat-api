#!/bin/bash

# Parse command line arguments
PUSH=false
REPO=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            PUSH=true
            REPO="$2"
            if [ -z "$REPO" ]; then
                echo "Error: --push requires a repository argument"
                echo "Usage: $0 [--push <repo>[:<tag>]]"
                exit 1
            fi
            shift 2
            ;;
        *)
            echo "Usage: $0 [--push <repo>[:<tag>]]"
            exit 1
            ;;
    esac
done
# Check if buildkit_20 already exists before creating it
if ! docker buildx inspect buildkit_20 &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v0.20.2 --name buildkit_20
fi

touch scripts/pinned-packages-frontend-builder.txt scripts/pinned-packages-backend-builder.txt scripts/pinned-packages-runtime.txt
git rev-parse HEAD > .GIT_REV

# Read private-chat frontend version and PostHog configuration from build-config.toml
if [ -f "build-config.toml" ]; then
    PRIVATE_CHAT_FRONTEND_VERSION=$(grep -E '^\s*private_chat_frontend_version\s*=' build-config.toml | awk -F'"' '{print $2}' | head -n1)
    POSTHOG_KEY=$(grep -E '^\s*posthog_key\s*=' build-config.toml | awk -F'"' '{print $2}' | head -n1)
    POSTHOG_HOST=$(grep -E '^\s*posthog_host\s*=' build-config.toml | awk -F'"' '{print $2}' | head -n1)
fi

if [ -z "$PRIVATE_CHAT_FRONTEND_VERSION" ]; then
    echo "Error: private-chat frontend version not found in build-config.toml"
    exit 1
fi
echo "Using private-chat frontend version: ${PRIVATE_CHAT_FRONTEND_VERSION}"

if [ -z "$POSTHOG_KEY" ]; then
    echo "Warning: PostHog key not found in build-config.toml"
fi
if [ -z "$POSTHOG_HOST" ]; then
    echo "Warning: PostHog host not found in build-config.toml"
fi

GIT_COMMIT_TIMESTAMP=$(git log -1 --format=%ct)
echo "Using git commit timestamp: ${GIT_COMMIT_TIMESTAMP}"

TEMP_TAG="private-chat-temp:$(date +%s)"
docker buildx build --builder buildkit_20 --no-cache --platform linux/amd64 \
    --build-arg SOURCE_DATE_EPOCH="${GIT_COMMIT_TIMESTAMP}" \
    --build-arg PRIVATE_CHAT_FRONTEND_VERSION="${PRIVATE_CHAT_FRONTEND_VERSION}" \
    --build-arg POSTHOG_KEY="${POSTHOG_KEY}" \
    --build-arg POSTHOG_HOST="${POSTHOG_HOST}" \
    --output type=oci,dest=./oci.tar,rewrite-timestamp=true \
    --output type=docker,name="$TEMP_TAG",rewrite-timestamp=true .

if [ "$?" -ne 0 ]; then
    echo "Build failed"
    rm .GIT_REV
    exit 1
fi

echo "Build completed, manifest digest:"
echo ""
skopeo inspect oci-archive:./oci.tar | jq .Digest
echo ""

if [ "$PUSH" = true ]; then
    echo "Pushing image to $REPO..."
    skopeo copy --insecure-policy oci-archive:./oci.tar docker://"$REPO"
    echo "Image pushed successfully to $REPO"
else
    echo "To push the image to a registry, run:"
    echo ""
    echo " $0 --push <repo>[:<tag>]"
    echo ""
    echo "Or use skopeo directly:"
    echo ""
    echo " skopeo copy --insecure-policy oci-archive:./oci.tar docker://<repo>[:<tag>]"
    echo "" 
fi
echo ""

# Extract package information from the built image
echo "Extracting package information from built image: $TEMP_TAG"
# Extract frontend builder stage package information
docker run --rm "$TEMP_TAG" cat /app/pinned-packages-frontend-builder.txt > scripts/pinned-packages-frontend-builder.txt
echo "Package information extracted to scripts/pinned-packages-frontend-builder.txt ($(wc -l < scripts/pinned-packages-frontend-builder.txt) packages)"
# Extract backend builder stage package information
docker run --rm "$TEMP_TAG" cat /app/pinned-packages-backend-builder.txt > scripts/pinned-packages-backend-builder.txt
echo "Package information extracted to scripts/pinned-packages-backend-builder.txt ($(wc -l < scripts/pinned-packages-backend-builder.txt) packages)"
# Extract runtime stage package information
docker run --rm --entrypoint bash "$TEMP_TAG" -c "dpkg -l | grep '^ii' | awk '{print \$2\"=\"\$3}' | sort" > scripts/pinned-packages-runtime.txt
echo "Package information extracted to scripts/pinned-packages-runtime.txt ($(wc -l < scripts/pinned-packages-runtime.txt) packages)"

# Clean up the temporary image from Docker daemon
docker rmi "$TEMP_TAG" 2>/dev/null || true

rm .GIT_REV
