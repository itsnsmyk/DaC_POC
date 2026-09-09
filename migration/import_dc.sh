#!/usr/bin/env bash
# Adopt existing Kibana rules into Terraform state.
# Run AFTER `terraform init` and BEFORE the first apply.
#
# Import ID format is <space_id>/<kibana_internal_id>. Verify against your
# provider build with a single rule before running the whole file:
#   terraform state show 'module.detections...this["<uid>"]'
set -euo pipefail
cd "$(dirname "$0")/../terraform/live"
terraform init -reconfigure -backend-config=backends/dc.hcl

