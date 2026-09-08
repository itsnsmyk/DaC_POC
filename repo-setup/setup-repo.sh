#!/usr/bin/env bash
#
# Initialise the DaC repository safely.
#
# The order here is deliberate. .gitignore has to exist before the first
# `git add`, and the secret scan has to run before the first commit, because
# git history is effectively permanent — a password committed and then removed
# is still in the reflog, in every clone, and in any CI cache.
#
#   ./setup-repo.sh                                  # checks only
#   ./setup-repo.sh --apply                          # init + first commit
#   ./setup-repo.sh --apply --remote git@github.com:org/detection-as-code.git
#
set -euo pipefail

APPLY=0
REMOTE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)  APPLY=1; shift ;;
    --remote) REMOTE="$2"; shift 2 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$(dirname "$HERE")" 2>/dev/null || cd .
REPO="$(pwd)"

G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
step(){ printf '\n%s== %s ==%s\n' "$G" "$*" "$N"; }
warn(){ printf '%s   !! %s%s\n' "$Y" "$*" "$N"; }
fail(){ printf '%s   XX %s%s\n' "$R" "$*" "$N"; PROBLEMS=$((PROBLEMS+1)); }
note(){ printf '%s   %s%s\n' "$D" "$*" "$N"; }
PROBLEMS=0

echo "Repository root: $REPO"
[[ $APPLY -eq 0 ]] && printf '%sDRY RUN%s — checks only, nothing written.\n' "$Y" "$N"

# ---------------------------------------------------------------------------
step "1. Ignore rules must exist before anything is staged"

if [[ -f "$HERE/gitignore.template" ]]; then
  if [[ $APPLY -eq 1 ]]; then
    if [[ -f .gitignore ]]; then
      cat "$HERE/gitignore.template" >> .gitignore
      # de-duplicate while preserving order
      awk '!seen[$0]++' .gitignore > .gitignore.tmp && mv .gitignore.tmp .gitignore
    else
      cp "$HERE/gitignore.template" .gitignore
    fi
    cp -n "$HERE/gitattributes.template" .gitattributes 2>/dev/null || true
    cp -n "$HERE/CODEOWNERS.template" CODEOWNERS 2>/dev/null || true
  fi
  note ".gitignore / .gitattributes / CODEOWNERS"
else
  warn "templates not found next to this script"
fi

# ---------------------------------------------------------------------------
step "2. Secret scan"
# Not a substitute for a real scanner, but it catches the specific mistakes this
# repository layout invites.

scan() {
  local pattern="$1" label="$2"
  local hits
  hits=$(grep -rniE "$pattern" . \
          --include='*.tf' --include='*.tfvars' --include='*.hcl' \
          --include='*.yaml' --include='*.yml' --include='*.json' \
          --include='*.sh' --include='Jenkinsfile' \
          --exclude-dir=.git --exclude-dir=.terraform --exclude-dir=node_modules \
          2>/dev/null | grep -viE '(example|placeholder|changeme|your-|TODO|#)' | head -5 || true)
  if [[ -n "$hits" ]]; then
    fail "$label"
    printf '%s      %s%s\n' "$D" "$(echo "$hits" | head -3 | tr '\n' '~' | sed 's/~/\n      /g')" "$N"
  fi
}

scan '(password|passwd)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{6,}' "hard-coded password"
scan '(api_?key|apikey)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9+/=]{20,}' "hard-coded API key"
scan 'BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY' "private key material"
scan 'aws_(secret_)?access_key' "AWS credentials"

if [[ -f local/.env ]]; then
  fail "local/.env contains stack passwords and must not be committed"
  if [[ $APPLY -eq 1 ]]; then
    cp local/.env local/.env.example
    sed -i.bak -E 's/^(ELASTIC_PASSWORD|KIBANA_SYSTEM_PASSWORD|KIBANA_ENCRYPTION_KEY)=.*/\1=CHANGE_ME/' local/.env.example
    rm -f local/.env.example.bak
    note "wrote local/.env.example — commit that, keep local/.env ignored"
    PROBLEMS=$((PROBLEMS-1))
  fi
fi

[[ $PROBLEMS -eq 0 ]] && note "no obvious secrets found"

# ---------------------------------------------------------------------------
step "3. rule_id namespace"
# Every derived rule_id is uuidv5(namespace, uid). The namespace must be yours,
# generated once, and never changed — changing it recreates every rule that does
# not carry a pinned rule_id.

DEFAULT_NS="1b671a64-40d5-491e-99b0-da01ff1f3341"
if grep -rq "$DEFAULT_NS" terraform/ 2>/dev/null; then
  NEW_NS="$(uuidgen 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())')"
  if [[ $APPLY -eq 1 ]]; then
    grep -rl "$DEFAULT_NS" terraform/ tools/ 2>/dev/null | while read -r f; do
      sed -i.bak "s/$DEFAULT_NS/$NEW_NS/g" "$f" && rm -f "$f.bak"
    done
    note "namespace replaced with $NEW_NS"
    warn "record this UUID somewhere durable. Losing it is recoverable;"
    warn "changing it later recreates every rule and destroys alert history."
  else
    warn "still using the example namespace $DEFAULT_NS — would replace with a fresh UUID"
  fi
else
  note "namespace already customised"
fi

# ---------------------------------------------------------------------------
step "4. Git repository"

if [[ -d .git ]]; then
  note "already a git repository"
else
  if [[ $APPLY -eq 1 ]]; then
    git init -q
    git symbolic-ref HEAD refs/heads/main
    note "initialised, default branch 'main'"
  else
    note "would run: git init && default branch main"
  fi
fi

if [[ $APPLY -eq 1 ]]; then
  # Signed commits: the audit trail is only as good as the identity behind it.
  if git config user.signingkey >/dev/null 2>&1; then
    git config commit.gpgsign true
    note "commit signing enabled (key already configured)"
  else
    warn "no signing key configured. For a regulated environment set one up:"
    warn "  git config user.signingkey <KEY>  &&  git config commit.gpgsign true"
  fi
fi

# ---------------------------------------------------------------------------
step "5. Validate before committing"

if [[ -f tools/precheck.py ]]; then
  if python3 tools/precheck.py >/dev/null 2>&1; then
    note "precheck passes"
  else
    warn "precheck reports problems — run 'python3 tools/precheck.py' and fix before committing"
  fi
fi

# ---------------------------------------------------------------------------
step "6. First commit"

if [[ $PROBLEMS -gt 0 ]]; then
  printf '\n%sRefusing to commit: %d secret-scan problem(s) above.%s\n' "$R" "$PROBLEMS" "$N"
  echo "Fix them first. Anything committed here is permanent."
  exit 1
fi

if [[ $APPLY -eq 1 ]]; then
  git add -A
  cat > /tmp/dac-commit-msg <<'MSG'
Initial commit: detection-as-code baseline

Rules and exceptions as YAML under detections/, deployed by Terraform from
terraform/deployments/detections/ to one target per cluster.

Note for future audits: every rule appears created at this commit. Rule content
predating the repository carries its original Kibana rule_id, so the deployed
identity is continuous even though the git history starts here.
MSG
  git commit -q -F /tmp/dac-commit-msg
  rm -f /tmp/dac-commit-msg
  note "committed $(git rev-parse --short HEAD)"

  if [[ -n "$REMOTE" ]]; then
    git remote add origin "$REMOTE" 2>/dev/null || git remote set-url origin "$REMOTE"
    note "remote 'origin' -> $REMOTE"
    echo
    echo "Push with:  git push -u origin main"
  fi
else
  echo "   would: git add -A && git commit"
fi

# ---------------------------------------------------------------------------
step "Next"
cat <<'MSG'
On the hosting side, before anyone else clones:

  1. Protect main: no direct pushes, require PR + 1 approval from a CODEOWNER,
     require the CI check to pass, require signed commits.
  2. Make the repo private. Detection logic tells an attacker exactly what you
     do and do not detect.
  3. Add repo secrets / Jenkins credentials for the Kibana accounts. Never a
     tfvars file.
MSG
