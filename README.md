# Elastic Detection as Code — Terraform + Git + Jenkins

Rules live in YAML. Terraform renders them into `elasticstack_kibana_security_detection_rule`
resources keyed by a **human-readable uid**, and Jenkins rolls them out to DC then DR
with pre-checks, a blast-radius guard, post-checks and a cross-cluster parity proof.

---

## 1. Why YAML (and not JSON or TOML)

| | JSON | TOML | **YAML** |
|---|---|---|---|
| Comments (tuning rationale, review dates) | no | yes | **yes** |
| Multi-line queries without `\n` escaping | no | yes | **yes** (`\|` block scalars) |
| Native Terraform decode | `jsondecode` | **none** — needs an external data source or a build-step converter | **`yamldecode`** |
| Deep nesting (MITRE threat → technique → subtechnique) | verbose | awkward for arrays of tables | **clean** |
| Diff readability in a PR | poor | good | **good** |

JSON is out: no comments, and a 15-line EQL query becomes one unreadable escaped string —
exactly the reason your UUID-named files were painful to review.

TOML is the format Elastic's own [`detection-rules`](https://github.com/elastic/detection-rules)
repo uses, which matters if you ever want its authoring/validation CLI. But **Terraform has
no `tomldecode`**, so choosing TOML means a conversion step between the source of truth and
the IaC — one more thing to break. YAML is decoded natively by `yamldecode()`, so the file on
disk *is* the input to the resource, with no intermediate artifact.

**Portability, the requirement you actually asked about:** nothing in `rules/*.yaml` is
Terraform-specific. There are no HCL expressions, no `${}`, no provider attribute names that
don't also exist in the Kibana API. If you replace Terraform with Ansible, a Python
Kibana-API pusher, or `detection-rules`, you rewrite `terraform/` and keep `rules/` untouched.
That is the whole point of keeping logic in data files rather than in `.tf`.

If you later want `detection-rules` for authoring, add a ~40-line `scripts/toml_to_yaml.py`
and keep YAML as the committed source of truth. Don't make TOML the primary format.

---

## 2. Fixing the UUID problem

### What changes on disk

```
BEFORE  rules/a4f1c2d3-9e8b-4a71-b0c5-1d2e3f4a5b6c.json
AFTER   rules/network/Threshold_IOC_Network_Intrusion_Detection.yaml
```

`scripts/migrate_from_export.py` does this conversion for your existing exports.
The filename is generated from the rule's `name`, routed into a subdirectory by its
`OS:`/`Domain:` tag, with acronyms preserved (`IOC`, `LSASS`, `DNS`, `RDP` — extend the
`ACRONYMS` set for your estate).

### Three identifiers, and which one you own

| | Who sets it | Changes per cluster | Do you ever type it? |
|---|---|---|---|
| **filename** | you | no | yes, constantly |
| `uid` | you | no | occasionally (`-target`, state) |
| `rule_id` | you *or* derived | no | almost never |
| `id` (Kibana internal) | Kibana | **yes** | **never again** |

The `id` — the alphanumeric string your old filenames were built from — is Kibana's internal
saved-object reference. It's different on DC and DR for the same logical rule, which is why
naming files after it was unworkable. It appears nowhere in this repo.

```yaml
uid: threshold-ioc-network-intrusion-detection
rule_id: a4f1c2d3-9e8b-4a71-b0c5-1d2e3f4a5b6c   # preserved from your Kibana export
name: Threshold IOC Network Intrusion Detection
```

The module resolves identity in priority order:

```hcl
rule_id = try(each.value.rule_id, uuidv5(var.rule_id_namespace, each.key))
```

- **Migrated rules** pin the `rule_id` they already have, so Terraform *adopts* the live rule
  instead of creating a duplicate next to it. Alert history and attached exceptions survive.
- **New rules** written from scratch omit `rule_id` and get a deterministic one derived from
  their `uid` — identical on DC and DR, computed locally, no API lookup.

Both kinds coexist in one repo. `rules.lock.json` records which is which:

```json
"rules":   { "threshold-ioc-network-intrusion-detection": "a4f1c2d3-9e8b-4a71-b0c5-1d2e3f4a5b6c" },
"sources": { "threshold-ioc-network-intrusion-detection": "explicit" }
```

### What you can and can't rename

**Filename — rename freely.** It carries no meaning to Terraform. `make check` passes.

**`name` — rename freely.** It's a plain attribute; Terraform plans an in-place update.

**`uid` — needs a `moved` block.** It's the `for_each` key, so changing it plans a
destroy + create. Add the block to `terraform/live/moved.tf` first, then change the uid,
then `--update-lock`, all in one PR:

```hcl
moved {
  from = module.detections.elasticstack_kibana_security_detection_rule.this["old-uid"]
  to   = module.detections.elasticstack_kibana_security_detection_rule.this["new-uid"]
}
```

Without it the pre-check fails and tells you exactly this.

**`rule_id` — never edit a pinned one.** It orphans the live rule and creates a stranger
alongside it. The pre-check treats any change to a pinned `rule_id` as an error, and also
fails if two uids claim the same `rule_id`.

### Migration runbook

```bash
# 1. export what you have (or point at your existing UUID.json directory)
python3 scripts/migrate_from_export.py --input ./old-rules --dry-run   # review the renames
python3 scripts/migrate_from_export.py --input ./old-rules --out rules

# 2. review migration/mapping.csv (old_file -> new_file, uid, rule_id) and skim the YAML
# 3. resolve the TODO_map_connector_* placeholders into envs/*.tfvars
# 4. create any exceptions/*.yaml the warnings flagged

python3 scripts/precheck.py --update-lock
bash migration/import_dc.sh          # adopt live rules into Terraform state
make plan CLUSTER=dc                 # MUST show 0 to add, 0 to destroy
```

That last plan is the gate. Anything other than zero-add/zero-destroy means a rule didn't
adopt cleanly — fix it before applying, or you'll create duplicates in production.

> Two things to verify against your provider build before the first real run:
> ```
> terraform providers schema -json | \
>   jq '.provider_schemas[].resource_schemas.elasticstack_kibana_security_detection_rule.block.attributes | keys'
> ```
> that `rule_id` is settable, and that the `terraform import` ID format is
> `<space_id>/<kibana_id>` — try one rule before running the whole import script.
> If `rule_id` turns out to be computed-only, drop that line from `rules.tf` and rely purely
> on `terraform import`; readable filenames and uids are unaffected either way.

---

## 3. Layout

```
rules/                        source of truth — portable, IaC-agnostic
  _defaults.yaml              inherited by every rule; rule-level keys win
  network/Threshold_IOC_Network_Intrusion_Detection.yaml     <- migrated (rule_id pinned)
  windows/Service_Account_Interactive_Login.yaml             <- new (rule_id derived)
  windows/ linux/ network/ cloud/   directories are for humans; they carry no meaning
exceptions/                   exception lists + their items, same uid pattern
schemas/rule.schema.json      what a valid rule looks like
rules.lock.json               uid -> rule_id pins (committed, CI-enforced)

terraform/
  modules/detections/         reads YAML, emits rules + exceptions
  live/
    main.tf                   ONE root config for every cluster
    envs/{dc,dr,dev}.tfvars   per-cluster endpoints, connector IDs, tags
    backends/{dc,dr,dev}.hcl  per-cluster state (partial backend)

scripts/
  migrate_from_export.py      UUID.json -> Readable_Name.yaml, preserving rule_id
  precheck.py                 content validation + uid/rule_id immutability
  plan_guard.py               blast-radius budget on terraform plan JSON
  postcheck.py                per-cluster verification after apply
  drift_compare.py            DC vs DR parity proof
Jenkinsfile
```

**Adding a fourth cluster is two files**: `envs/<name>.tfvars` and `backends/<name>.hcl`.
No module changes, no copy-pasted root configs.

---

## 4. DC/DR strategy

**One root config, one state file per cluster, applied sequentially.** Not provider aliases
in a single state.

Rationale: a single state holding both clusters means a DR outage blocks DC deployments, one
state lock serialises everything, and a partial apply leaves both sides in one state file
you now have to untangle. Separate states let you run `SKIP_DR=true` during DR maintenance
and reconcile later — DC keeps shipping detections.

The pipeline applies **DC → post-check DC → DR → post-check DR → parity**. DR never gets
applied if DC's verification failed, so you don't propagate a bad rule to both sides.

Per-rule targeting is in the YAML:

```yaml
targets: [dc]        # canary a noisy rule on DC only
# targets: [dc, dr]  # default, from _defaults.yaml
```

`enabled_override = false` in `dr.tfvars` gives you an active/passive posture: rules are
deployed and identical on DR, but dormant so they don't double-alert while DC is primary.
Failover then becomes a one-line change instead of a deployment.

---

## 5. Pre-checks (`scripts/precheck.py`)

Runs before Terraform is even initialised, so failures cost seconds:

- JSON Schema conformance (`schemas/rule.schema.json`)
- `uid` format, uniqueness, and **immutability vs `rules.lock.json`**
- duplicate rule names
- per-type field rules — `esql` must not set `index`; `threshold` needs `threshold.value`;
  `machine_learning` needs a job id and anomaly threshold
- **look-back sanity**: `from` must reach further back than `interval`, or the rule silently
  drops events between runs. This one catches real production gaps.
- severity ↔ risk_score coherence
- MITRE tactic/technique/sub-technique ID format
- every `exceptions:` reference resolves to an existing list

Then `plan_guard.py` reads `terraform show -json` and fails if the plan destroys or replaces
more than `MAX_DESTROY` resources — the guard against a deleted directory wiping your ruleset.

The gap worth knowing: **the Terraform provider does not validate query syntax.** It hands
the rule to Kibana and reports whatever Kibana says. So the pipeline has a
`Query dry-run (dev cluster)` stage that applies the full ruleset to a dev cluster and runs
the post-check there first. That is the only reliable place to catch a malformed EQL/ES|QL
query before production.

---

## 6. Post-checks (`scripts/postcheck.py`, `scripts/drift_compare.py`)

Post-checks read the **repo**, not the Terraform state, so they catch provider bugs and
out-of-band Kibana edits rather than just confirming Terraform agrees with itself.

`postcheck.py` per cluster:
- every targeted rule exists at its derived `rule_id`
- `name`/`type`/`severity`/`risk_score`/`interval`/`enabled` match the YAML
- declared exception lists are attached, and their items actually exist
- after a settle window, no rule sits in `failed` or `partial failure` execution status
- no orphan `Managed: Terraform` rules that the repo no longer declares

`drift_compare.py` — the one that proves DC/DR sync. Pulls all Terraform-managed rules from
both clusters, normalises away legitimate per-cluster differences (internal `id`, timestamps,
`version`, connector IDs, `Site:` tags), hashes each rule and diffs. Reports left-only,
right-only and field-level content drift. Run it on a nightly Jenkins job too, not just after
deploys — that's how you catch someone hand-editing a rule in the DR Kibana UI.

---

## 7. Day-to-day

```bash
make new-rule UID=win-lsass-memory-access OS=windows
$EDITOR rules/windows/Win_Lsass_Memory_Access.yaml
make check                       # pre-checks, seconds
make plan CLUSTER=dc             # plan + blast-radius guard
git commit && open a PR          # CODEOWNERS -> detection engineering review
```

On merge to `main`, Jenkins does the rest.

Removing a rule is deliberate friction: delete the file **and** run
`python3 scripts/precheck.py --update-lock` in the same PR. Without the lock update the
build fails, which forces the destruction to be visible in review.

Rollback is `git revert` + re-run. The `rule_id` is derived from the uid, so a reverted rule
comes back with the same identity rather than as a new rule.

---

## 8. Setup checklist

- [ ] `uuidgen` once → store as Jenkins credential `elastic-dac-rule-id-namespace`, and set
      it as the default in `variables.tf`. Never change it.
- [ ] Confirm `rule_id` is settable (§2) on provider 0.16.4.
- [ ] Create a dedicated Kibana role/API key per cluster, scoped to the Security app only.
      Jenkins credentials: `elastic-dc-kibana`, `elastic-dr-kibana`, `elastic-dev-kibana`.
- [ ] Replace the placeholder endpoints, connector IDs and S3 backend in
      `terraform/live/envs/*.tfvars` and `backends/*.hcl`.
- [ ] Migrate existing rules with `scripts/migrate_from_export.py` and run the generated
      `migration/import_dc.sh` before the first apply, or Terraform will create duplicates
      alongside your live rules. See §2 for the full runbook.
- [ ] Branch protection on `main`: require the PR check, require review from a CODEOWNER,
      no direct pushes.
- [ ] Schedule `drift_compare.py` nightly as a separate Jenkins job.
