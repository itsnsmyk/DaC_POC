#!/usr/bin/env bash
#
# Tidy the working tree before the first commit.
#
# Run this from the repository root, before `git init`. Everything it does is
# either recovering a file that was misplaced during the download, or removing
# something that should never enter history in the first place.
#
#   bash prep.sh            # dry run
#   bash prep.sh --apply
#
set -uo pipefail
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
step(){ printf '\n%s== %s ==%s\n' "$G" "$*" "$N"; }
act(){  printf '   %s\n' "$*"; }
warn(){ printf '%s   !! %s%s\n' "$Y" "$*" "$N"; }
note(){ printf '%s   %s%s\n' "$D" "$*" "$N"; }
do_(){ [[ $APPLY -eq 1 ]] && "$@"; return 0; }

TFD="terraform/deployments/detections"
STRAY="mnt/user-data/outputs/elastic-dac/terraform/live"

[[ $APPLY -eq 0 ]] && printf '%sDRY RUN — nothing will change.%s\n' "$Y" "$N"

# ---------------------------------------------------------------------------
step "1. Recover the original root Terraform files from mnt/"
# These extracted with their full archive path instead of landing at the repo
# root, so the organise step could not find them and wrote approximations
# instead. The originals win.

for f in variables.tf outputs.tf; do
  if [[ -f "$STRAY/$f" ]]; then
    if [[ -f "$TFD/$f" ]] && diff -q "$STRAY/$f" "$TFD/$f" >/dev/null 2>&1; then
      note "$f identical, nothing to recover"
    else
      act "restoring $TFD/$f from mnt/ (was regenerated)"
      if [[ -f "$TFD/$f" ]]; then
        printf '%s      differences:%s\n' "$D" "$N"
        diff "$TFD/$f" "$STRAY/$f" 2>/dev/null | head -12 | sed 's/^/      /'
      fi
      do_ cp "$STRAY/$f" "$TFD/$f"
    fi
  fi
done

if [[ -d mnt ]]; then
  # Anything else hiding in there? Do not delete blind.
  OTHER=$(find mnt -type f ! -path "$STRAY/*" 2>/dev/null)
  if [[ -n "$OTHER" ]]; then
    warn "mnt/ holds files not accounted for — review before deleting:"
    printf '      %s\n' $OTHER
  else
    act "removing mnt/ (contents recovered)"
    do_ rm -rf mnt
  fi
fi

# ---------------------------------------------------------------------------
step "2. Remove one-shot scripts"
# These reorganised the tree. They have done their job, and keeping them invites
# someone to run them again against an already-organised repo.
for f in dirstructure.sh dirstrcuture.sh organise.sh restructure.sh; do
  [[ -e "$f" ]] && { act "rm $f"; do_ rm -f "$f"; }
done

# ---------------------------------------------------------------------------
step "3. Empty directories"
# Git does not track directories, only files. Empty ones vanish on clone unless
# they hold something — so keep the ones that are part of the taxonomy and drop
# the ones that are accidents.

# "Empty" means no real content. A .gitkeep left by the organise step does not
# count as content.
holds_nothing() {
  [[ -d "$1" ]] || return 1
  [[ -z "$(find "$1" -mindepth 1 ! -name .gitkeep -print -quit 2>/dev/null)" ]]
}

holds_nothing tools/dac && {
  act "rm -rf tools/dac (empty — your tools are the standalone versions)"
  do_ rm -rf tools/dac; }

holds_nothing detections/rules/uncategorised && {
  act "rm -rf detections/rules/uncategorised (nothing landed there)"
  do_ rm -rf detections/rules/uncategorised; }

for d in detections/rules/application detections/rules/cloud detections/rules/identity \
         docs/adr docs/runbooks terraform/modules/detections/examples/minimal; do
  if [[ -d "$d" && -z "$(ls -A "$d" 2>/dev/null)" ]]; then
    act "touch $d/.gitkeep"
    do_ touch "$d/.gitkeep"
  fi
done

# ---------------------------------------------------------------------------
step "4. Verify path rewrites actually landed"
# If the organise step missed one of these, terraform still works locally but
# breaks the moment someone clones fresh.

check() {
  local file="$1" pattern="$2" label="$3"
  [[ -f "$file" ]] || { warn "$file missing"; return; }
  if grep -qE "$pattern" "$file"; then
    note "$label ok"
  else
    warn "$file: $label NOT found — check this file by hand"
  fi
}
check "$TFD/main.tf" 'source *= *"\.\./\.\./modules/detections"' "module source depth"
check "$TFD/main.tf" 'detections/rules'                          "rules_dir path"
check Makefile       'terraform/deployments/detections'          "Makefile terraform path"
check Makefile       'tools/'                                    "Makefile tools path"
check Jenkinsfile    'terraform/deployments/detections'          "Jenkinsfile terraform path"

# The root module needs its own provider requirements. main.tf carries them in
# this layout, but check rather than assume.
if [[ -f "$TFD/versions.tf" ]] || grep -q 'required_providers' "$TFD/main.tf" 2>/dev/null; then
  note "root module declares required_providers"
else
  warn "$TFD has no required_providers — terraform init will fail"
fi

# ---------------------------------------------------------------------------
step "5. Content still valid"
if command -v python3 >/dev/null; then
  python3 - <<'PY'
import glob, json, sys
try:
    import yaml
except ImportError:
    print("   \033[2mPyYAML not installed, skipping content check\033[0m"); sys.exit(0)

bad = 0
for f in glob.glob("detections/**/*.yaml", recursive=True):
    try: yaml.safe_load(open(f))
    except Exception as e: print(f"   \033[31m!! {f}: {e}\033[0m"); bad += 1
for f in glob.glob("detections/**/*.json", recursive=True):
    try: json.load(open(f))
    except Exception as e: print(f"   \033[31m!! {f}: {e}\033[0m"); bad += 1
if not bad:
    n = len(glob.glob("detections/rules/**/*.yaml", recursive=True))
    print(f"   \033[2m{n} rule files parse cleanly\033[0m")
PY
fi

# ---------------------------------------------------------------------------
step "Summary"
if [[ $APPLY -eq 0 ]]; then
  echo "Re-run with --apply, then continue with setup-repo.sh."
else
  cat <<'MSG'
Tree is ready. Next:

  bash repo-setup/setup-repo.sh --apply --remote <your-repo-url>
  git push -u origin main
MSG
fi
