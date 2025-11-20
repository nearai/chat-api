#!/bin/bash
set -e

# Script to build the frontend locally for development

FRONTEND_DIR="frontend"
FRONTEND_REPO="https://github.com/nearai/private-chat"
FRONTEND_DIST_TARGET="crates/api/frontend/dist"

echo "Building frontend for local development..."

# Check if frontend directory exists
if [ ! -d "$FRONTEND_DIR" ]; then
    echo "Cloning frontend repository..."
    git clone "$FRONTEND_REPO" "$FRONTEND_DIR"
fi

# Navigate to frontend directory
cd "$FRONTEND_DIR"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# Build the frontend
echo "Building frontend..."
npm run build

# Copy to the location expected by rust-embed
cd ..
echo "Copying build artifacts to $FRONTEND_DIST_TARGET..."
mkdir -p "$(dirname "$FRONTEND_DIST_TARGET")"
rm -rf "$FRONTEND_DIST_TARGET"
cp -r "$FRONTEND_DIR/dist" "$FRONTEND_DIST_TARGET"

echo "✅ Frontend build complete!"
echo "You can now build the Rust API with: cargo build --release --bin api"

