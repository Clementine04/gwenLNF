#!/usr/bin/env bash
# Build script for Render

# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create upload directory
mkdir -p static/uploads
