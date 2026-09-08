#!/usr/bin/env bash
# Adopt existing Kibana rules into Terraform state.
# Run AFTER `terraform init` and BEFORE the first apply.
#
# Import ID format is <space_id>/<kibana_internal_id>. Verify against your
# provider build with a single rule before running the whole file:
#   terraform state show 'module.detections...this["<uid>"]'
set -euo pipefail
cd "$(dirname "$0")/../terraform/live"
terraform init -reconfigure -backend-config=backends/dr.hcl

terraform import -var-file=envs/dr.tfvars "module.detections.elasticstack_kibana_security_detection_rule.this[\"threshold-ioc-network-intrusion-detection\"]" "default/8b7c6d5e-4f3a-2b1c-9d8e-7f6a5b4c3d2e"
terraform import -var-file=envs/dr.tfvars "module.detections.elasticstack_kibana_security_detection_rule.this[\"suspicious-lsass-memory-access-via-dll-injection\"]" "default/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a6b"
