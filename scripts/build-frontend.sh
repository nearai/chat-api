#!/bin/bash
set -e

# Script to build the frontend locally for development

FRONTEND_DIR="frontend"
FRONTEND_REPO="https://github.com/nearai/private-chat"
FRONTEND_DIST_TARGET="crates/api/frontend/dist"

# Read private-chat frontend version from build-config.toml
if [ -f "build-config.toml" ]; then
    PRIVATE_CHAT_FRONTEND_VERSION=$(grep -E '^\s*private_chat_frontend_version\s*=' build-config.toml | awk -F'"' '{print $2}' | head -n1)
fi
if [ -z "$PRIVATE_CHAT_FRONTEND_VERSION" ]; then
    echo "Error: private-chat frontend version not found in build-config.toml"
    exit 1
fi
echo "Using private-chat frontend version: ${PRIVATE_CHAT_FRONTEND_VERSION}"

echo "Building frontend for local development..."

# Check if frontend directory exists
if [ ! -d "$FRONTEND_DIR" ]; then
    echo "Cloning frontend repository..."
    git clone "$FRONTEND_REPO" "$FRONTEND_DIR"
fi

# Navigate to frontend directory
cd "$FRONTEND_DIR"
git fetch origin
git checkout $PRIVATE_CHAT_FRONTEND_VERSION

# Check if node_modules exists
echo "Installing frontend dependencies..."
pnpm install --frozen-lockfile

# Build the frontend
echo "Building frontend..."
pnpm run build

# Copy to the location expected by rust-embed
cd ..
echo "Copying build artifacts to $FRONTEND_DIST_TARGET..."
mkdir -p "$(dirname "$FRONTEND_DIST_TARGET")"
rm -rf "$FRONTEND_DIST_TARGET"
cp -r "$FRONTEND_DIR/dist" "$FRONTEND_DIST_TARGET"

echo "✅ Frontend build complete!"
echo "You can now build the Rust API with: cargo build --release --bin api"
