#!/usr/bin/env python3
"""Adopt a rule created in the Kibana UI into the repository.

Terraform only manages what is in its state, so a rule someone builds in the UI
is invisible to the pipeline: no plan entry, no drift, no audit trail. This pulls
it out of Kibana, writes it as a rule file, and prints the `terraform import`
command that hands the live object over to Terraform without recreating it.

The rule keeps the rule_id Kibana already gave it, so adoption is a no-op against
the running rule rather than a delete-and-replace.

    # everything in the space that Terraform does not already manage
    python3 tools/adopt.py --cluster dc --list

    # adopt one, by Kibana id or by name
    python3 tools/adopt.py --cluster dc --id 49882c35-663c-4829-b503-f33f6a49eef2
    python3 tools/adopt.py --cluster dc --name "Demo Rule Test"

    # adopt everything unmanaged
    python3 tools/adopt.py --cluster dc --all
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from migrate_from_export import (  # noqa: E402
    BlockDumper,
    KEY_ORDER,
    route_dir,
    to_filename,
    to_uid,
)

MANAGED_TAG = os.environ.get("MANAGED_TAG", "Managed: Terraform")

# Kibana owns these; they must not end up in a source-of-truth file.
SERVER_OWNED = {
    "id", "created_at", "created_by", "updated_at", "updated_by",
    "version", "revision", "execution_summary", "immutable", "outcome",
    "rule_source", "meta", "throttle", "output_index", "namespace",
    "related_integrations", "required_fields", "alias_target_id",
    "alias_purpose", "response_actions",
}

# Tags the module adds itself. Carrying them in the file would be duplication
# that drifts the moment tag_prefix changes.
GENERATED_TAG_PREFIXES = ("Managed:", "Site:", "Cluster:", "Rule UID:")


def kibana_session(cluster: str) -> tuple[requests.Session, str, str]:
    prefix = cluster.upper()
    base = os.environ[f"{prefix}_KIBANA_URL"].rstrip("/")
    space = os.environ.get(f"{prefix}_SPACE_ID", "default")

    session = requests.Session()
    session.headers.update({"kbn-xsrf": "true", "Content-Type": "application/json"})
    session.auth = (
        os.environ[f"{prefix}_KIBANA_USERNAME"],
        os.environ[f"{prefix}_KIBANA_PASSWORD"],
    )
    session.verify = os.environ.get(f"{prefix}_VERIFY_TLS", "true").lower() != "false"
    return session, base, space


def space_url(base: str, space: str, path: str) -> str:
    return f"{base}/s/{space}{path}" if space != "default" else f"{base}{path}"


def fetch_all_rules(session, base, space) -> list[dict]:
    rules, page = [], 1
    while True:
        response = session.get(
            space_url(base, space, "/api/detection_engine/rules/_find"),
            params={"page": page, "per_page": 100,
                    "sort_field": "name", "sort_order": "asc"},
            timeout=60,
        )
        response.raise_for_status()
        body = response.json()
        rules.extend(body.get("data", []))
        if page * 100 >= body.get("total", 0):
            return rules
        page += 1


def is_unmanaged(rule: dict) -> bool:
    """A rule Terraform did not create, and that is not an Elastic prebuilt."""
    if rule.get("immutable") or rule.get("rule_source", {}).get("type") == "external":
        return False
    return MANAGED_TAG not in (rule.get("tags") or [])


def allowed_fields(schema_path: Path) -> set[str]:
    schema = json.loads(schema_path.read_text())
    return set(schema.get("properties", {}))


def to_rule_file(rule: dict, cluster: str, allowed: set[str],
                 defaults: dict) -> tuple[dict, list[str]]:
    """Convert a Kibana rule into a repository rule document."""
    notes: list[str] = []
    doc = {k: v for k, v in rule.items()
           if k not in SERVER_OWNED and v not in (None, "", [], {})}

    doc["uid"] = to_uid(rule["name"])
    # Keep the identity Kibana already has, so importing is an adoption.
    doc["rule_id"] = rule["rule_id"]

    doc["tags"] = [t for t in doc.get("tags", [])
                   if not t.startswith(GENERATED_TAG_PREFIXES)]
    if not doc["tags"]:
        doc.pop("tags")

    exceptions = doc.pop("exceptions_list", [])
    for entry in exceptions:
        notes.append(
            f"attached to exception list '{entry.get('list_id')}' — add its uid "
            f"under `exceptions:` once that list exists in detections/exceptions/"
        )

    actions = doc.pop("actions", [])
    if actions:
        doc["actions"] = [
            {"connector": f"TODO_map_connector_{a.get('id','?')[:8]}",
             "group": a.get("group", "default"),
             "params": a.get("params", {})}
            for a in actions
        ]
        notes.append(f"{len(actions)} action(s) need a logical connector name")

    # The rule exists on one cluster only; say so rather than assuming both.
    doc["targets"] = [cluster]

    # Anything the schema does not know about would fail precheck.
    for key in sorted(set(doc) - allowed):
        notes.append(f"dropped unsupported field '{key}' (value: {doc[key]!r})")
        doc.pop(key)

    for key, value in (defaults or {}).items():
        if key != "targets" and doc.get(key) == value:
            doc.pop(key, None)

    ordered = {k: doc[k] for k in KEY_ORDER if k in doc}
    ordered.update({k: v for k, v in doc.items() if k not in ordered})
    return ordered, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--rules-dir", default="detections/rules")
    parser.add_argument("--schema", default="detections/schemas/rule.schema.json")
    parser.add_argument("--id", help="Kibana internal id (from the rule's URL)")
    parser.add_argument("--name", help="Exact rule name")
    parser.add_argument("--all", action="store_true", help="Adopt every unmanaged rule")
    parser.add_argument("--list", action="store_true", help="Show what is unmanaged, change nothing")
    args = parser.parse_args()

    session, base, space = kibana_session(args.cluster)
    everything = fetch_all_rules(session, base, space)
    unmanaged = [r for r in everything if is_unmanaged(r)]

    if args.list:
        print(f"{len(everything)} custom rules in space '{space}', "
              f"{len(unmanaged)} not managed by Terraform:\n")
        for rule in unmanaged:
            print(f"  {rule['name']}")
            print(f"    kibana id : {rule['id']}")
            print(f"    rule_id   : {rule['rule_id']}")
            print(f"    created   : {rule.get('created_by')} on {rule.get('created_at','')[:19]}")
        return 0

    if args.id:
        selected = [r for r in everything if r["id"] == args.id]
    elif args.name:
        selected = [r for r in everything if r["name"] == args.name]
    elif args.all:
        selected = unmanaged
    else:
        print("Pass --id, --name, --all or --list")
        return 2

    if not selected:
        print("No matching rule. Run with --list to see what is there.")
        return 1

    defaults_path = Path(args.rules_dir) / "_defaults.yaml"
    defaults = yaml.safe_load(defaults_path.read_text()) if defaults_path.exists() else {}
    allowed = allowed_fields(Path(args.schema))

    imports = []
    for rule in selected:
        doc, notes = to_rule_file(rule, args.cluster, allowed, defaults)
        subdir = route_dir(rule, "uncategorised")
        target = Path(args.rules_dir) / subdir / (to_filename(rule["name"]) + ".yaml")
        target.parent.mkdir(parents=True, exist_ok=True)

        header = (
            f"# Adopted from the Kibana UI on cluster '{args.cluster}'.\n"
            f"# Originally created by {rule.get('created_by')} "
            f"on {rule.get('created_at','')[:19]}.\n"
            f"# rule_id preserved, so Terraform adopts the live rule rather than\n"
            f"# recreating it. Review before merging.\n"
        )
        target.write_text(
            header + yaml.dump(doc, Dumper=BlockDumper, sort_keys=False,
                               allow_unicode=True, width=4096)
        )
        print(f"wrote {target}")
        for note in notes:
            print(f"  note: {note}")

        imports.append((doc["uid"], f"{space}/{rule['id']}"))

    print("\nNext:\n")
    print("  python3 tools/precheck.py --update-lock\n")
    print("  # adopt the live objects into state, or the next apply creates duplicates")
    for uid, import_id in imports:
        print(f"  terraform -chdir=terraform/deployments/detections import \\")
        print(f"    -var-file=targets/vps-{args.cluster}.tfvars \\")
        print(f"    'module.detections.elasticstack_kibana_security_detection_rule.this[\"{uid}\"]' \\")
        print(f"    '{import_id}'")
    print("\n  ./vps/02-run-pipeline.sh --plan-only   # expect 0 to add, 0 to destroy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
