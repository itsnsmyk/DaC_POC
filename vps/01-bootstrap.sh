#!/usr/bin/env bash
#
# Prepare an existing Elastic/Kibana deployment for the DaC pipeline.
#
# Unlike the docker-compose rig, this targets a cluster you already run. It only
# adds what the pipeline needs and tells you what it found.
#
#   export KIBANA_URL=http://136.244.84.124:5601
#   export ES_URL=http://136.244.84.124:9200
#   export ELASTIC_USER=elastic
#   export ELASTIC_PASSWORD='...'
#   ./01-bootstrap.sh
#
set -euo pipefail

: "${ELASTIC_USER:=elastic}"
: "${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}"

# Elasticsearch 8.x and 9.x enable HTTPS with a self-signed CA by default, while
# Kibana still serves plain HTTP. Guessing wrong gives "Empty reply from server",
# so probe instead of assuming. Running on the VPS itself, localhost also avoids
# the firewall entirely.
ES_HOST="${ES_HOST:-localhost}"
KB_HOST="${KB_HOST:-localhost}"
CURL_CA=""

find_ca() {
  local c
  for c in /etc/elasticsearch/certs/http_ca.crt            /usr/share/elasticsearch/config/certs/http_ca.crt; do
    [[ -r "$c" ]] && { echo "$c"; return; }
  done
  # Readable only by root on a package install; copy it somewhere usable.
  for c in /etc/elasticsearch/certs/http_ca.crt; do
    if sudo -n test -r "$c" 2>/dev/null; then
      sudo cp "$c" /tmp/es_http_ca.crt && sudo chmod 644 /tmp/es_http_ca.crt
      echo /tmp/es_http_ca.crt; return
    fi
  done
}

probe() {  # probe <url> -> 0 if it answers as Elasticsearch/Kibana
  curl -sS --max-time 8 ${CURL_CA:+--cacert "$CURL_CA"} \
       -u "$ELASTIC_USER:$ELASTIC_PASSWORD" "$1" >/dev/null 2>&1
}

if [[ -z "${ES_URL:-}" ]]; then
  CA="$(find_ca || true)"
  if [[ -n "$CA" ]]; then CURL_CA="$CA"; fi
  if   probe "https://$ES_HOST:9200";                    then ES_URL="https://$ES_HOST:9200"
  elif CURL_CA="" && curl -sSk --max-time 8 -u "$ELASTIC_USER:$ELASTIC_PASSWORD" \
         "https://$ES_HOST:9200" >/dev/null 2>&1;        then ES_URL="https://$ES_HOST:9200"; ES_INSECURE=1
  elif probe "http://$ES_HOST:9200";                     then ES_URL="http://$ES_HOST:9200"
  else
    echo "Cannot reach Elasticsearch on $ES_HOST:9200 over http or https."
    echo "Check:  sudo ss -tlnp | grep 9200"
    exit 1
  fi
fi
[[ -z "${KIBANA_URL:-}" ]] && KIBANA_URL="http://$KB_HOST:5601"
ES_INSECURE="${ES_INSECURE:-0}"

echo "Elasticsearch : $ES_URL${CURL_CA:+  (CA $CURL_CA)}${ES_INSECURE:+  [cert not verified]}"
echo "Kibana        : $KIBANA_URL"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TFD="$REPO/terraform/deployments/detections"
AUTH="$ELASTIC_USER:$ELASTIC_PASSWORD"

G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
step(){ printf '\n%s== %s ==%s\n' "$G" "$*" "$N"; }
note(){ printf '%s   %s%s\n' "$D" "$*" "$N"; }
warn(){ printf '%s   !! %s%s\n' "$Y" "$*" "$N"; }

CA_OPT=(); [[ -n "$CURL_CA" ]] && CA_OPT=(--cacert "$CURL_CA")
[[ "$ES_INSECURE" == "1" ]] && CA_OPT=(-k)

es(){ curl -sS "${CA_OPT[@]}" -u "$AUTH" -H 'Content-Type: application/json' "$@"; }
kb(){ curl -sS -u "$AUTH" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; }

step "Connectivity"
VER=$(es "$ES_URL" | grep -o '"number" *: *"[^"]*"' | cut -d'"' -f4)
[[ -n "$VER" ]] || { echo "${R}cannot reach Elasticsearch at $ES_URL${N}"; exit 1; }
note "Elasticsearch $VER"
kb "$KIBANA_URL/api/status" | grep -q '"level":"available"' \
  && note "Kibana available" || { echo "${R}Kibana not available${N}"; exit 1; }

step "License"
LIC=$(es "$ES_URL/_license" | grep -o '"type" *: *"[^"]*"' | head -1 | cut -d'"' -f4)
note "current: $LIC"
case "$LIC" in
  basic)
    warn "Detection rules work on Basic, but connectors (actions) need Gold+"
    warn "and machine_learning rules need Platinum."
    read -r -p "   Start a 30-day trial now? [y/N] " ans
    if [[ "$ans" == "y" ]]; then
      es -XPOST "$ES_URL/_license/start_trial?acknowledge=true" | head -c 160; echo
    fi
    ;;
  trial|platinum|enterprise) note "sufficient for every rule type" ;;
  gold) warn "connectors fine; machine_learning rules will fail" ;;
esac

step "Detection engine initialisation"
# Kibana creates the alerts indices lazily. Rules created before that happens
# report a partial failure on their first run.
SIG=$(kb "$KIBANA_URL/api/detection_engine/index" -w '%{http_code}' -o /dev/null 2>/dev/null || echo "000")
if [[ "$SIG" == "200" ]]; then
  note "alerts indices present"
else
  warn "alerts indices not initialised (HTTP $SIG)"
  warn "open $KIBANA_URL/app/security/rules once in a browser, then re-run"
fi

step "DR space"
if kb "$KIBANA_URL/api/spaces/space/dr" | grep -q '"id":"dr"'; then
  note "space 'dr' already exists"
else
  kb -XPOST "$KIBANA_URL/api/spaces/space" -d '{
    "id":"dr","name":"DR",
    "description":"Second deployment target for DaC parity testing"
  }' >/dev/null && note "created space 'dr'"
fi

step "Terraform service account"
# Least privilege beats reusing elastic. This role covers exactly what the
# provider touches.
es -XPUT "$ES_URL/_security/role/dac_terraform" -d '{
  "cluster": ["monitor"],
  "indices": [{ "names": [".alerts-security*", ".lists-*", ".items-*"],
                "privileges": ["read","view_index_metadata"] }],
  "applications": [{
    "application": "kibana-.kibana",
    "privileges": ["feature_siem.all","feature_actions.all","feature_savedObjectsManagement.all"],
    "resources": ["space:default","space:dr"]
  }]
}' >/dev/null && note "role dac_terraform"

DAC_PASS="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
es -XPUT "$ES_URL/_security/user/dac_terraform" -d "{
  \"password\":\"$DAC_PASS\",
  \"roles\":[\"dac_terraform\"],
  \"full_name\":\"Detection as Code deployer\"
}" >/dev/null && note "user dac_terraform created"

step "Substitute connector"
# Rules referencing soc_pagerduty fail the module precondition unless that
# logical name maps to a real connector id. A server-log connector needs no
# external service, so the rule deploys unchanged and you can swap in the real
# PagerDuty id later without touching the YAML.
CONN_ID=$(kb -XPOST "$KIBANA_URL/api/actions/connector" -d '{
  "name":"DaC POC server log",
  "connector_type_id":".server-log",
  "config":{},"secrets":{}
}' | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[[ -n "$CONN_ID" ]] && note "connector $CONN_ID" || warn "connector creation failed (license?)"

step "Terraform wiring"
mkdir -p "$TFD/targets" "$TFD/state"

cat > "$TFD/backend_override.tf" <<'OVR'
# VPS ONLY - generated by vps/01-bootstrap.sh. Do not commit.
# Replaces the S3 backend so the POC needs no AWS account. State path is passed
# per target: terraform init -reconfigure -backend-config=path=state/dc.tfstate
terraform {
  backend "local" {}
}
OVR

# The committed main.tf assumes TLS-verified endpoints. On a default 8.x/9.x
# install Elasticsearch uses a self-signed CA and Kibana is plain HTTP, so
# override the whole provider block rather than editing tracked files.
{
  echo '# VPS ONLY - generated by vps/01-bootstrap.sh. Do not commit.'
  echo 'provider "elasticstack" {'
  echo '  kibana {'
  echo "    endpoints = [\"$KIBANA_URL\"]"
  echo '  }'
  echo '  elasticsearch {'
  echo "    endpoints = [\"$ES_URL\"]"
  if [[ "$ES_INSECURE" == "1" ]]; then
    echo '    insecure  = true'
  elif [[ -n "$CURL_CA" ]]; then
    echo "    ca_file   = \"$CURL_CA\""
  fi
  echo '  }'
  echo '}'
} > "$TFD/provider_override.tf"
note "provider_override.tf (ES over ${ES_URL%%:*}${CURL_CA:+, CA pinned}${ES_INSECURE:+, unverified})"

for target in dc dr; do
  space="default"; [[ "$target" == "dr" ]] && space="dr"
  cat > "$TFD/targets/vps-${target}.tfvars" <<VARS
cluster_role           = "${target}"
kibana_endpoint        = "${KIBANA_URL}"
elasticsearch_endpoint = "${ES_URL}"
space_id               = "${space}"
connector_ids = {
  soc_pagerduty = "${CONN_ID}"
  soc_slack     = "${CONN_ID}"
}
tag_prefix = ["Managed: Terraform", "Site: VPS-${target^^}"]
VARS
  note "targets/vps-${target}.tfvars"
done

for p in 'backend_override.tf' 'provider_override.tf' 'targets/vps-*.tfvars' 'terraform/deployments/detections/state/'; do
  grep -qxF "$p" "$REPO/.gitignore" 2>/dev/null || echo "$p" >> "$REPO/.gitignore"
done

step "Credentials for the pipeline"
cat > "$REPO/.dac-env" <<ENV
# Generated by vps/01-bootstrap.sh. Gitignored. source this before running.
export KIBANA_USERNAME='dac_terraform'
export KIBANA_PASSWORD='$DAC_PASS'
export ELASTICSEARCH_USERNAME='dac_terraform'
export ELASTICSEARCH_PASSWORD='$DAC_PASS'
export DC_KIBANA_URL='$KIBANA_URL'
export DC_SPACE_ID='default'
export DC_KIBANA_USERNAME='dac_terraform'
export DC_KIBANA_PASSWORD='$DAC_PASS'
export DR_KIBANA_URL='$KIBANA_URL'
export DR_SPACE_ID='dr'
export DR_KIBANA_USERNAME='dac_terraform'
export DR_KIBANA_PASSWORD='$DAC_PASS'
ENV
chmod 600 "$REPO/.dac-env"
grep -qxF '.dac-env' "$REPO/.gitignore" 2>/dev/null || echo '.dac-env' >> "$REPO/.gitignore"
note "wrote .dac-env (chmod 600, gitignored)"

step "Ready"
cat <<MSG
  source .dac-env
  ./vps/02-run-pipeline.sh

If a rule reports "partial failure" after deploying, the index it queries has no
data. With Fleet already installed, add the System / Windows / Elastic Defend
integrations so the logs-* data streams exist.
MSG
