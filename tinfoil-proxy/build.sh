#!/bin/bash

# Build the tinfoil-proxy Docker image and extract the binary

set -e

echo "Building tinfoil-proxy Docker image..."
docker build -t tinfoil-proxy:latest .

echo "Extracting binary from Docker image..."
mkdir -p dist

# Create a container from the image (don't run it)
CONTAINER_ID=$(docker create tinfoil-proxy:latest)

# Copy the binary out
docker cp $CONTAINER_ID:/tinfoil-proxy dist/tinfoil-proxy

# Remove the container
docker rm $CONTAINER_ID

# Make it executable
chmod +x dist/tinfoil-proxy

echo "Binary extracted to: dist/tinfoil-proxy"
echo "Done!"