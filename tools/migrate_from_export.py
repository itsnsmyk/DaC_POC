#!/usr/bin/env python3
"""
Convert UUID-named Kibana rule exports into human-readable YAML.

    a4f1c2d3-9e8b-4a71-b0c5-1d2e3f4a5b6c.json
        -> rules/network/Threshold_IOC_Network_Intrusion_Detection.yaml

The filename is derived from the rule's `name`. The rule's existing `rule_id` is
carried into the YAML verbatim, so Terraform ADOPTS the rule that is already
running in Kibana rather than creating a duplicate alongside it. Alert history,
exceptions and rule-level overrides survive the migration.

Accepts either:
  * a directory of per-rule .json files (the UUID.json layout you have today)
  * a Kibana .ndjson bulk export (Security -> Rules -> Export)

Usage:
    # look first, write nothing
    python3 scripts/migrate_from_export.py --input ./old-rules --dry-run

    # write the YAML tree + an import script + a mapping report
    python3 scripts/migrate_from_export.py --input ./old-rules --out rules

    # then adopt the live rules into Terraform state
    bash migration/import_dc.sh
"""
import argparse
import csv
import json
import os
import re
import sys
import uuid
from collections import Counter
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Fields Kibana owns. None of these belong in a source-of-truth file: they are
# server-generated, per-cluster, or recomputed on every write.
# ---------------------------------------------------------------------------
DROP = {
    "id", "created_at", "created_by", "updated_at", "updated_by",
    "version", "revision", "execution_summary", "immutable", "outcome",
    "rule_source", "meta", "throttle", "output_index", "namespace",
    "related_integrations", "required_fields", "alias_target_id",
    "alias_purpose", "response_actions",
}

# Acronyms to keep upper-case in generated filenames. Extend for your estate.
ACRONYMS = {
    "IOC", "IOA", "DNS", "TLS", "SSL", "SSH", "RDP", "SMB", "LDAP", "HTTP",
    "HTTPS", "FTP", "VPN", "AWS", "GCP", "IAM", "EC2", "S3", "API", "CLI",
    "DLL", "PS", "WMI", "UAC", "LSASS", "NTLM", "PII", "C2", "TTP", "URL",
    "IP", "IDS", "IPS", "WAF", "EDR", "MFA", "SSO", "OS", "SQL", "XSS",
}

# tag prefix -> directory. First match wins; order matters.
TAG_ROUTES = [
    ("OS: Windows", "windows"),
    ("OS: Linux", "linux"),
    ("OS: macOS", "macos"),
    ("Data Source: AWS", "cloud"),
    ("Data Source: Azure", "cloud"),
    ("Data Source: GCP", "cloud"),
    ("Domain: Cloud", "cloud"),
    ("Domain: Network", "network"),
    ("Domain: Identity", "identity"),
    ("Domain: Endpoint", "endpoint"),
]

# Order keys are written in, so every generated file reads the same way.
KEY_ORDER = [
    "uid", "rule_id", "name", "description",
    "type", "language", "query", "saved_id", "index", "filters",
    "threshold", "new_terms_fields", "history_window_start",
    "machine_learning_job_id", "anomaly_threshold",
    "threat_index", "threat_query", "threat_mapping", "threat_language",
    "threat_indicator_path",
    "enabled", "severity", "risk_score", "interval", "from", "to",
    "max_signals", "author", "license", "tags", "false_positives",
    "references", "note", "setup",
    "rule_name_override", "timestamp_override", "building_block_type",
    "investigation_fields", "threat", "exceptions", "actions", "targets",
]


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------
def to_filename(name, rule_type=None, type_prefix=False):
    """'Threshold IOC Network Intrusion Detection' -> 'Threshold_IOC_Network_Intrusion_Detection'"""
    cleaned = re.sub(r"[^\w\s-]", " ", name)
    tokens = [t for t in re.split(r"[\s\-_]+", cleaned) if t]

    out = []
    for t in tokens:
        if t.upper() in ACRONYMS:
            out.append(t.upper())
        elif t.isupper() and len(t) > 1:
            out.append(t)                      # already an acronym we don't know
        else:
            out.append(t[:1].upper() + t[1:].lower())

    if type_prefix and rule_type:
        prefix = rule_type.replace("_", " ").title().replace(" ", "")
        if out and out[0].lower() != prefix.lower():
            out.insert(0, prefix)

    return "_".join(out)[:120]


def to_uid(name):
    """'Threshold IOC Network Intrusion Detection' -> 'threshold-ioc-network-intrusion-detection'"""
    slug = re.sub(r"[^\w\s-]", "", name.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:80].strip("-")


def route_dir(rule, default_dir):
    for tag in rule.get("tags") or []:
        for prefix, target in TAG_ROUTES:
            if tag.strip().lower() == prefix.lower():
                return target
    return default_dir


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_export(path):
    """Yield (source_label, rule_dict) from .json files or an .ndjson export."""
    p = Path(path)
    files = [p] if p.is_file() else sorted(
        list(p.rglob("*.json")) + list(p.rglob("*.ndjson"))
    )

    for f in files:
        text = f.read_text()
        if f.suffix == ".ndjson":
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                # Kibana appends an export summary object; it has no rule name.
                if obj.get("exported_count") is not None or "rule_id" not in obj:
                    continue
                yield f"{f.name}:{obj.get('rule_id')}", obj
        else:
            obj = json.loads(text)
            if isinstance(obj, list):
                for o in obj:
                    yield f.name, o
            else:
                yield f.name, obj


# ---------------------------------------------------------------------------
# Transform
# ---------------------------------------------------------------------------
def transform(rule, defaults, known_exception_lists, warnings, src):
    out = {k: v for k, v in rule.items() if k not in DROP and v not in (None, [], {})}

    name = out.get("name")
    out["uid"] = to_uid(name)

    # Preserve the identity the rule already has in Kibana. This is the line
    # that turns a destroy-and-recreate into an in-place adoption.
    if rule.get("rule_id"):
        out["rule_id"] = rule["rule_id"]
    else:
        warnings.append(f"{src}: export has no rule_id; a new one will be derived from the uid")

    # exceptions_list -> logical uid references
    ex = out.pop("exceptions_list", []) or []
    resolved, unresolved = [], []
    for e in ex:
        lid = e.get("list_id")
        if lid in known_exception_lists:
            resolved.append(known_exception_lists[lid])
        elif lid:
            unresolved.append(lid)
    if resolved:
        out["exceptions"] = resolved
    for lid in unresolved:
        warnings.append(
            f"{src}: exception list '{lid}' is attached in Kibana but has no file "
            f"under exceptions/. Create it, then add its uid to this rule's `exceptions:`."
        )

    # actions -> logical connector names; real IDs live in the per-cluster tfvars
    actions = out.pop("actions", []) or []
    if actions:
        out["actions"] = [
            {
                "connector": f"TODO_map_connector_{a.get('id', 'unknown')[:8]}",
                "group": a.get("group", "default"),
                "params": a.get("params", {}),
            }
            for a in actions
        ]
        warnings.append(
            f"{src}: {len(actions)} action(s) migrated with placeholder connector names. "
            f"Rename them and add the real IDs to terraform/live/envs/*.tfvars."
        )

    # Strip values identical to _defaults.yaml so files stay short and the
    # defaults remain a single place to change.
    for k, v in (defaults or {}).items():
        if k != "targets" and out.get(k) == v:
            out.pop(k, None)

    ordered = {k: out[k] for k in KEY_ORDER if k in out}
    ordered.update({k: v for k, v in out.items() if k not in ordered})
    return ordered


class BlockDumper(yaml.SafeDumper):
    """Emit multi-line strings as `|` blocks so queries stay readable and diffable."""


def _str_repr(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


BlockDumper.add_representer(str, _str_repr)


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Directory of UUID.json files, or an .ndjson export.")
    ap.add_argument("--out", default="detections/rules")
    ap.add_argument("--exceptions-dir", default="detections/exceptions")
    ap.add_argument("--defaults", default="rules/_defaults.yaml")
    ap.add_argument("--default-dir", default="uncategorised",
                    help="Subdirectory for rules whose tags don't route anywhere.")
    ap.add_argument("--type-prefix", action="store_true",
                    help="Prefix filenames with the rule type, e.g. Threshold_...")
    ap.add_argument("--space-id", default="default")
    ap.add_argument("--clusters", default="dc,dr",
                    help="Emit one terraform import script per cluster.")
    ap.add_argument("--migration-dir", default="migration")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    defaults_path = Path(args.defaults)
    defaults = yaml.safe_load(defaults_path.read_text()) if defaults_path.exists() else {}

    known_exception_lists = {}
    if Path(args.exceptions_dir).is_dir():
        for f in Path(args.exceptions_dir).rglob("*.yaml"):
            e = yaml.safe_load(f.read_text())
            if e and e.get("list_id"):
                known_exception_lists[e["list_id"]] = e["uid"]

    warnings, rows = [], []
    seen_uid, seen_path = {}, {}
    name_counts = Counter()

    for src, rule in load_export(args.input):
        name = rule.get("name")
        if not name:
            warnings.append(f"{src}: no 'name' field, skipped")
            continue

        doc = transform(rule, defaults, known_exception_lists, warnings, src)
        uid = doc["uid"]

        # Collisions: two rules whose names slugify identically.
        if uid in seen_uid:
            name_counts[uid] += 1
            uid = f"{uid}-{name_counts[uid] + 1}"
            doc["uid"] = uid
            warnings.append(
                f"{src}: name collides with '{seen_uid[doc['uid'].rsplit('-', 1)[0]]}'; "
                f"uid disambiguated to '{uid}'. Rename one of the rules."
            )
        seen_uid[uid] = src

        subdir = route_dir(rule, args.default_dir)
        fname = to_filename(name, rule.get("type"), args.type_prefix) + ".yaml"
        target = Path(args.out) / subdir / fname
        if str(target) in seen_path:
            target = target.with_name(f"{target.stem}_{uid[-6:]}.yaml")
        seen_path[str(target)] = uid

        rows.append({
            "old_file": src,
            "kibana_id": rule.get("id", ""),
            "rule_id": doc.get("rule_id", "<derived>"),
            "new_file": str(target),
            "uid": uid,
            "name": name,
            "type": rule.get("type", ""),
            "enabled": rule.get("enabled", ""),
        })

        if not args.dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            header = (
                f"# Migrated from {src}\n"
                f"# rule_id is the identity Kibana already knows this rule by - do not edit it.\n"
                f"# uid is the Terraform key. Rename the FILE freely; renaming the uid\n"
                f"# requires a `moved` block (see README section 2).\n"
            )
            target.write_text(
                header + yaml.dump(doc, Dumper=BlockDumper, sort_keys=False,
                                   allow_unicode=True, width=4096)
            )

    # ----- reports ---------------------------------------------------------
    mig = Path(args.migration_dir)
    if not args.dry_run:
        mig.mkdir(parents=True, exist_ok=True)

        with open(mig / "mapping.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["old_file"])
            w.writeheader()
            w.writerows(rows)

        # terraform import: adopt live rules into state without recreating them.
        for cluster in [c.strip() for c in args.clusters.split(",") if c.strip()]:
            lines = [
                "#!/usr/bin/env bash",
                "# Adopt existing Kibana rules into Terraform state.",
                "# Run AFTER `terraform init` and BEFORE the first apply.",
                "#",
                "# Import ID format is <space_id>/<kibana_internal_id>. Verify against your",
                "# provider build with a single rule before running the whole file:",
                "#   terraform state show 'module.detections...this[\"<uid>\"]'",
                "set -euo pipefail",
                'cd "$(dirname "$0")/../terraform/live"',
                f'terraform init -reconfigure -backend-config=backends/{cluster}.hcl',
                "",
            ]
            for r in rows:
                if not r["kibana_id"]:
                    lines.append(f'# SKIP {r["uid"]}: export had no internal id; '
                                 f'look it up in Kibana or let Terraform create it')
                    continue
                addr = ('module.detections.elasticstack_kibana_security_detection_rule.'
                        f'this[\\"{r["uid"]}\\"]')
                lines.append(
                    f'terraform import -var-file=envs/{cluster}.tfvars '
                    f'"{addr}" "{args.space_id}/{r["kibana_id"]}"'
                )
            path = mig / f"import_{cluster}.sh"
            path.write_text("\n".join(lines) + "\n")
            path.chmod(0o755)

    # ----- console ---------------------------------------------------------
    for r in rows[:25]:
        print(f"  {r['old_file']:<45} -> {r['new_file']}")
    if len(rows) > 25:
        print(f"  ... and {len(rows) - 25} more (full list in {mig}/mapping.csv)")

    if warnings:
        print()
        for w in warnings:
            print(f"[WARN ] {w}")

    print(f"\n{len(rows)} rules converted"
          f"{' (dry run, nothing written)' if args.dry_run else ''}, "
          f"{len(warnings)} warning(s)")

    if not args.dry_run and rows:
        print(f"\nNext:")
        print(f"  1. review {mig}/mapping.csv and skim the generated YAML")
        print(f"  2. python3 scripts/precheck.py --update-lock")
        print(f"  3. bash {mig}/import_dc.sh")
        print(f"  4. make plan CLUSTER=dc   # expect 0 to create, 0 to destroy")

    return 0


if __name__ == "__main__":
    sys.exit(main())
