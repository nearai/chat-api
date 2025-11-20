# Frontend build stage
FROM node:20-slim as frontend-builder

# Set working directory for frontend build
WORKDIR /frontend

# Clone the private-chat frontend repository
RUN apt-get update && apt-get install -y git && \
    git clone https://github.com/nearai/private-chat.git . && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies and build
RUN pnpm install && pnpm run build

# Rust build stage  
FROM rust:latest as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Copy the built frontend from the frontend-builder stage
COPY --from=frontend-builder /frontend/dist ./crates/api/frontend/dist

# Build the application in release mode
RUN cargo build --release --bin api

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 app

# Create app directory
WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/api /app/api

# Change ownership to app user
RUN chown -R app:app /app

# Switch to app user
USER app

# Expose the port
EXPOSE 3000

# Run the application
CMD ["./api"]
