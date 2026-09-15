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
        if not response.ok:
            raise SystemExit(
                f"Kibana returned {response.status_code} for _find:\n"
                f"  {response.text[:400]}"
            )
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


def fetch_exception_list(session, base, space, list_id, namespace):
    """The list object itself, or None if it has gone."""
    response = session.get(
        space_url(base, space, "/api/exception_lists"),
        params={"list_id": list_id, "namespace_type": namespace},
        timeout=30,
    )
    return response.json() if response.status_code == 200 else None


def fetch_exception_items(session, base, space, list_id, namespace):
    response = session.get(
        space_url(base, space, "/api/exception_lists/items/_find"),
        params={"list_id": list_id, "namespace_type": namespace, "per_page": 100},
        timeout=30,
    )
    if response.status_code != 200:
        return []
    return response.json().get("data", [])


def exception_to_document(remote_list, items, rule_name):
    """Turn a Kibana exception list into a repository document.

    A `rule_default` list is Kibana's implicit per-rule container, created by the
    "Add rule exception" button. It is bound to one rule, carries a generated
    UUID for a list_id, and exists only on the cluster where someone clicked.
    Converting it to a named shared list makes it reviewable, referenceable from
    several rules, and deployable to every target - so that is what we write.

    A list that is already shared keeps its list_id, so Terraform can adopt the
    existing object rather than creating a second one.
    """
    is_rule_default = remote_list.get("type") == "rule_default"

    if is_rule_default:
        name = f"{rule_name} Exceptions".strip()
        list_id = to_uid(name)
    else:
        name = remote_list.get("name") or remote_list["list_id"]
        list_id = remote_list["list_id"]

    document = {
        "uid": to_uid(name),
        "list_id": list_id,
        "name": name,
        "description": remote_list.get("description")
                       or f"Exceptions for {rule_name}.",
        "type": "detection",
        "namespace_type": remote_list.get("namespace_type", "single"),
    }
    if remote_list.get("tags"):
        document["tags"] = remote_list["tags"]

    document["items"] = []
    for item in items:
        document["items"].append({
            "uid": to_uid(item.get("name") or item["item_id"]),
            "item_id": item["item_id"] if not is_rule_default
                       else to_uid(item.get("name") or item["item_id"]),
            "name": item.get("name"),
            "description": item.get("description") or "Adopted from the Kibana UI.",
            "type": item.get("type", "simple"),
            "namespace_type": item.get("namespace_type", "single"),
            "entries": item["entries"],
            **({"tags": item["tags"]} if item.get("tags") else {}),
        })

    return document, is_rule_default


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

    # Populated by the caller once each attached list has been written out.
    doc.pop("exceptions_list", None)

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
    parser.add_argument("--exceptions-dir", default="detections/exceptions")
    parser.add_argument("--no-exceptions", action="store_true",
                        help="Adopt the rule only, leaving its exception lists behind.")
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

    exceptions_dir = Path(args.exceptions_dir)
    imports, orphans = [], []

    for rule in selected:
        doc, notes = to_rule_file(rule, args.cluster, allowed, defaults)

        # --- exceptions attached to this rule ------------------------------
        # Adopting a rule without its exceptions would be worse than not
        # adopting it: the next apply computes exceptions_list from the repo,
        # finds none, and silently detaches suppressions someone relies on.
        if not args.no_exceptions:
            references = []
            for entry in rule.get("exceptions_list") or []:
                list_id = entry.get("list_id")
                namespace = entry.get("namespace_type", "single")
                if not list_id:
                    continue

                remote = fetch_exception_list(session, base, space, list_id, namespace)
                if not remote:
                    notes.append(f"exception list '{list_id}' is attached but "
                                 f"could not be read; skipped")
                    continue

                items = fetch_exception_items(session, base, space, list_id, namespace)
                ex_doc, was_rule_default = exception_to_document(
                    remote, items, rule["name"]
                )

                ex_path = exceptions_dir / (to_filename(ex_doc["name"]) + ".yaml")
                ex_path.parent.mkdir(parents=True, exist_ok=True)
                ex_header = (
                    f"# Adopted with rule '{rule['name']}' from cluster "
                    f"'{args.cluster}'.\n"
                )
                if was_rule_default:
                    ex_header += (
                        f"# Was a rule_default list ({list_id}) created by the UI's\n"
                        f"# 'Add rule exception' button. Rewritten as a shared list so it\n"
                        f"# is reviewable and deploys to every target. The original is\n"
                        f"# now redundant - delete it once this is applied.\n"
                    )
                    orphans.append((list_id, namespace))
                else:
                    imports.append((
                        "elasticstack_kibana_security_exception_list",
                        ex_doc["uid"], f"{space}/{remote['id']}"
                    ))
                    for item in items:
                        imports.append((
                            "elasticstack_kibana_security_exception_item",
                            f"{ex_doc['uid']}/{to_uid(item.get('name') or item['item_id'])}",
                            f"{space}/{item['id']}"
                        ))

                ex_path.write_text(
                    ex_header + yaml.dump(ex_doc, Dumper=BlockDumper, sort_keys=False,
                                          allow_unicode=True, width=4096)
                )
                print(f"wrote {ex_path}  ({len(items)} item(s))")
                references.append(ex_doc["uid"])

            if references:
                doc["exceptions"] = references

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

        imports.append(("elasticstack_kibana_security_detection_rule",
                        doc["uid"], f"{space}/{rule['id']}"))

    print("\nNext:\n")
    print("  python3 tools/precheck.py --update-lock")
    print("  python3 tools/reconcile_state.py --cluster "
          f"{args.cluster} --apply   # imports everything below\n")

    if imports:
        print("  # or import by hand:")
        for resource, key, import_id in imports:
            print(f"  terraform -chdir=terraform/deployments/detections import \\")
            print(f"    -var-file=targets/vps-{args.cluster}.tfvars \\")
            print(f"    'module.detections.{resource}.this[\"{key}\"]' \\")
            print(f"    '{import_id}'")

    if orphans:
        print("\n  # after applying, remove the redundant rule_default list(s):")
        for list_id, namespace in orphans:
            print(f"  curl -sS -u \"$DC_KIBANA_USERNAME:$DC_KIBANA_PASSWORD\" "
                  f"-H 'kbn-xsrf: true' \\")
            print(f"    -XDELETE \"$DC_KIBANA_URL/api/exception_lists"
                  f"?list_id={list_id}&namespace_type={namespace}\"")

    print("\n  ./vps/02-run-pipeline.sh --plan-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
