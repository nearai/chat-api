# Stage 1: Copy pre-built frontend (built locally via npm/pnpm)
FROM scratch AS frontend-builder

# Copy the pre-built frontend distribution from local build
COPY frontend/dist /frontend/dist


# Stage 2: Rust build stage  
FROM rust:1.90.0-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS backend-builder

# Install pinned apt dependencies
RUN --mount=type=bind,source=scripts/pinned-packages-backend-builder.txt,target=/tmp/pinned-packages-backend-builder.txt,ro \
    set -e; \
    # Create a sources.list file pointing to a specific snapshot
    echo 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20250411T024939Z bookworm main' > /etc/apt/sources.list && \
    echo 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20250411T024939Z bookworm-security main' >> /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until && \
    # Create preferences file to pin all packages
    rm -rf /etc/apt/sources.list.d/debian.sources && \
    mkdir -p /etc/apt/preferences.d && \
    cat /tmp/pinned-packages-backend-builder.txt | while read line; do \
        pkg=$(echo $line | cut -d= -f1); \
        ver=$(echo $line | cut -d= -f2); \
        if [ ! -z "$pkg" ] && [ ! -z "$ver" ]; then \
            printf "Package: %s\nPin: version %s\nPin-Priority: 1001\n\n" "$pkg" "$ver" >> /etc/apt/preferences.d/pinned-packages; \
        fi; \
    done && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache

# Set the working directory
WORKDIR /app

# Fetch the latest pinned package list
RUN dpkg -l | grep '^ii' | awk '{print $2"="$3}' | sort > ./pinned-packages-backend-builder.txt

# Set the source date epoch to 0 to avoid timestamp changes
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY .cargo/ ./.cargo/

# Build the application in release mode
RUN cargo build --release --locked --bin api


# Stage 3: Runtime stage
FROM debian:bookworm-slim@sha256:78d2f66e0fec9e5a39fb2c72ea5e052b548df75602b5215ed01a17171529f706 AS runtime

# Bootstrap by installing ca-certificates which will be overridden by the pinned packages.
# Otherwise the source list cannot be fetched from the debian snapshot.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache

# Install pinned apt dependencies
RUN --mount=type=bind,source=scripts/pinned-packages-runtime.txt,target=/tmp/pinned-packages-runtime.txt,ro \
    set -e; \
    # Create a sources.list file pointing to a specific snapshot
    echo 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20250411T024939Z bookworm main' > /etc/apt/sources.list && \
    echo 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20250411T024939Z bookworm-security main' >> /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until && \
    # Create preferences file to pin all packages
    rm -rf /etc/apt/sources.list.d/debian.sources && \
    mkdir -p /etc/apt/preferences.d && \
    cat /tmp/pinned-packages-runtime.txt | while read line; do \
        pkg=$(echo $line | cut -d= -f1); \
        ver=$(echo $line | cut -d= -f2); \
        if [ ! -z "$pkg" ] && [ ! -z "$ver" ]; then \
            printf "Package: %s\nPin: version %s\nPin-Priority: 1001\n\n" "$pkg" "$ver" >> /etc/apt/preferences.d/pinned-packages; \
        fi; \
    done && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
        && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache

# Create app user
# Normalize /etc/shadow file last password change date to 0 for app user
RUN useradd -m -u 1000 app \
    && sed -i -r 's/^(app:[^:]*:)[0-9]+/\10/' /etc/shadow

# Create app directory
WORKDIR /app

# Copy the built binary
COPY --from=backend-builder --chmod=0775 /app/target/release/api /app/api

# Copy the migration SQL files
RUN mkdir -p /app/crates/database/src/migrations/sql
COPY --from=backend-builder --chmod=0664 /app/crates/database/src/migrations/sql/*.sql /app/crates/database/src/migrations/sql/

# Copy the built frontend from the frontend-builder stage
COPY --from=frontend-builder /frontend/dist /app/crates/api/frontend/dist

# Copy the pinned package list from builder stage
COPY --from=backend-builder --chmod=0664 /app/pinned-packages-backend-builder.txt /app/pinned-packages-backend-builder.txt

# Change ownership to app user
RUN chown -R app:app /app

# Switch to app user
USER app

# Expose the port
EXPOSE 3000

# Run the application
CMD ["./api"]
