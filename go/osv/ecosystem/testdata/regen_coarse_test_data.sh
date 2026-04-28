#!/bin/bash
set -e

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
MODULE_ROOT="$( cd "$SCRIPT_DIR/../../.." &> /dev/null && pwd )"

ZIP_URL="https://storage.googleapis.com/osv-vulnerabilities/all.zip"
TEMP_ZIP="$(mktemp)"

echo "Downloading all.zip..."
curl -o "$TEMP_ZIP" "$ZIP_URL"

echo "Extracting versions..."
# Run the Go command from the module root
(cd "$MODULE_ROOT" && go run ./cmd/extract_versions "$TEMP_ZIP" "$SCRIPT_DIR/all_versions.txt")

echo "Cleaning up..."
rm "$TEMP_ZIP"

echo "Done! Generated $SCRIPT_DIR/all_versions.txt"
