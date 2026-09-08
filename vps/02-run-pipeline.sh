#!/usr/bin/env bash
#
# Run the pipeline stages against the VPS cluster, in the same order Jenkins
# will. Prove it works here before wiring up Jenkins - otherwise a failure
# leaves you debugging two things at once.
#
#   source .dac-env
#   ./vps/02-run-pipeline.sh --plan-only     # what a PR build does
#   ./vps/02-run-pipeline.sh                 # full run, pauses before apply
#   ./vps/02-run-pipeline.sh --auto
#
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
TFD="terraform/deployments/detections"
TF="terraform -chdir=$TFD"

: "${DC_KIBANA_URL:?run 'source .dac-env' first}"

AUTO=0; PLAN_ONLY=0
for a in "$@"; do
  case "$a" in
    --auto) AUTO=1 ;;
    --plan-only) PLAN_ONLY=1 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

FAILED=""
stage(){ printf '\n\033[1;34m┌─ %s\033[0m\n' "$*"; }
ok(){    printf '\033[32m└─ ok\033[0m\n'; }
bad(){   printf '\033[31m└─ FAILED: %s\033[0m\n' "$1"; FAILED="$FAILED $1"; }

# Terraform reads Kibana credentials from the environment, so they never touch
# a tfvars file or the shell history.
export KIBANA_USERNAME KIBANA_PASSWORD

stage "1  Rule content validation"
python3 tools/precheck.py && ok || bad precheck

stage "2  Terraform format and validate"
$TF fmt -check -recursive -diff || { echo "run: $TF fmt -recursive"; FAILED="$FAILED fmt"; }
$TF init -reconfigure -input=false -backend-config=path=state/dc.tfstate >/dev/null 2>&1
$TF validate && ok || bad validate

[[ -n "$FAILED" ]] && { printf '\n\033[31mPre-checks failed:%s\033[0m\n' "$FAILED"; exit 1; }

plan_target(){
  local t="$1"
  # -reconfigure per target is what swaps the state file. Same shape as the
  # production flow, where it swaps the S3 backend config instead.
  $TF init -reconfigure -input=false -backend-config="path=state/${t}.tfstate" >/dev/null
  $TF plan -input=false -var-file="targets/vps-${t}.tfvars" -out="${t}.tfplan" || return 1
  $TF show -json "${t}.tfplan" > "$TFD/plan-${t}.json"
  python3 tools/plan_guard.py "$TFD/plan-${t}.json" --max-destroy 3
}

stage "3  Plan DC"; plan_target dc && ok || bad plan-dc
stage "4  Plan DR"; plan_target dr && ok || bad plan-dr

[[ -n "$FAILED" ]] && { printf '\n\033[31mPlan failed:%s\033[0m\n' "$FAILED"; exit 1; }
[[ $PLAN_ONLY -eq 1 ]] && { printf '\n\033[32mPlan-only complete.\033[0m\n'; exit 0; }

if [[ $AUTO -eq 0 ]]; then
  stage "5  Approval"
  read -r -p "Apply to DC and DR? [y/N] " reply
  [[ "$reply" == "y" ]] || { echo aborted; exit 0; }
fi

apply_target(){
  local t="$1"
  $TF init -reconfigure -input=false -backend-config="path=state/${t}.tfstate" >/dev/null
  $TF apply -input=false -auto-approve "${t}.tfplan"
}

stage "6  Apply DC"; apply_target dc && ok || bad apply-dc
[[ -n "$FAILED" ]] && { echo "DC failed - not touching DR"; exit 1; }

stage "7  Post-check DC"
python3 tools/postcheck.py --cluster dc --settle 90 && ok || bad postcheck-dc

stage "8  Apply DR"; apply_target dr && ok || bad apply-dr
stage "9  Post-check DR"
python3 tools/postcheck.py --cluster dr --settle 90 && ok || bad postcheck-dr

stage "10 DC/DR parity"
python3 tools/drift_compare.py --left dc --right dr --show-diff && ok || bad parity

if [[ -n "$FAILED" ]]; then
  printf '\n\033[31mPipeline FAILED:%s\033[0m\n' "$FAILED"; exit 1
fi
printf '\n\033[32mPassed. Rules: %s/app/security/rules\033[0m\n' "$DC_KIBANA_URL"
