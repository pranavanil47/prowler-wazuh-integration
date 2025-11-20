#!/bin/bash

BUCKET="(bucket name)"
LOCAL_DIR="/var/ossec/logs/prowler"
OUTPUT_PREFIX="output/json-ocsf"
S3_CMD="aws s3"

# Ensure local directory exists
mkdir -p "$LOCAL_DIR/tmp"

# Download all JSON files from S3
$S3_CMD sync "s3://$BUCKET/$OUTPUT_PREFIX/" "$LOCAL_DIR/tmp/" --exact-timestamps

# Copy new files to main log and archive
for file in "$LOCAL_DIR/tmp"/*.json; do
  echo "Processing file: $file"
  cat "$file" >> "$LOCAL_DIR/prowler-ocsf.log"
  mv "$file" "$LOCAL_DIR/$(basename "$file")"
done

# Delete remote copies to avoid duplication
$S3_CMD rm "s3://$BUCKET/$OUTPUT_PREFIX/" --recursive

echo "Sync and cleanup complete."
