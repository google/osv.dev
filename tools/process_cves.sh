#!/bin/bash -ex

cd ..

INPUT_FILE="vulnfeeds/cmd/cvelist2osv/Linux_2025.json"
OUTPUT_DIR="osv_output"
GO_PROGRAM="vulnfeeds/cmd/cvelist2osv/main.go"

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

# Check if jq is installed
if ! command -v jq &> /dev/null
then
    echo "jq could not be found. Please install jq to run this script."
    exit 1
fi

# Read the JSON file and process each CVE object in the array
jq -c '.[]' "$INPUT_FILE" | while IFS= read -r cve_object; do
  # Extract the CVE ID for logging
  cve_id=$(echo "$cve_object" | jq -r '.cveMetadata.cveId')
  echo "Processing $cve_id..."

  # Create a temporary file to hold the single CVE object
  tmp_file=$(mktemp)
  echo "$cve_object" > "$tmp_file"

  # Run the Go program with the temporary file as input
  go run "$GO_PROGRAM" -cve_json "$tmp_file" -out_dir "$OUTPUT_DIR" -out_format MinimalOSV

  # Remove the temporary file
  rm "$tmp_file"
done

echo "Finished processing all CVEs. Output is in the '$OUTPUT_DIR' directory."
