#!/bin/bash

# Change to Prowler CLI directory
cd /home/ubuntu/prowler-cli/

# Activate virtual environment
source venv/bin/activate

# Run Prowler and store in S3
timestamp=$(date +%Y%m%d%H%M%S)
bucket="(bucket name)"
output_dir="output"

prowler aws \
  --output-formats json-ocsf \
  --output-bucket "$bucket" \
  --output-directory "$output_dir"

# Deactivate virtual environment
deactivate
