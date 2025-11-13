#!/bin/sh
set -e

# Install docker CLI if not present
if ! command -v docker > /dev/null 2>&1; then
  echo "Installing docker CLI..."
  apk add --no-cache docker-cli
fi

# Start the application
exec npm start
