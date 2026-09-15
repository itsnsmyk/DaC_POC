#!/usr/bin/env python3
"""Import objects that exist in Kibana but are missing from Terraform state.

The problem this solves
-----------------------
Terraform only knows about objects in its state file. If a rule exists in Kibana
but not in state, `apply` tries to create it and Kibana answers 409 - rule_id
already exists. That aborts the apply midway, and because the pipeline runs
DC then DR, a 409 on DC stops DR from being touched at all.

That failure is avoidable: the object exists, the repo describes it, and the
only thing missing is the state entry. This runs before `plan` and imports it.

The safety property
-------------------
Only objects whose identity matches a rule ALREADY IN THE REPO are imported.
A rule someone created in the UI that has no corresponding file is never
adopted silently - it stays unmanaged and postcheck reports it. Otherwise this
would quietly bless unreviewed detection logic as approved, which is exactly
backwards for a change-controlled environment.

So the two cases are:
  * repo has it, Kibana has it, state does not  -> import (this script)
  * Kibana has it, repo does not                -> report it (postcheck)

Usage
-----
    python3 tools/reconcile_state.py --cluster dc              # report only
    python3 tools/reconcile_state.py --cluster dc --apply
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import requests
import yaml

RULE_RESOURCE = "elasticstack_kibana_security_detection_rule"
LIST_RESOURCE = "elasticstack_kibana_security_exception_list"
ITEM_RESOURCE = "elasticstack_kibana_security_exception_item"

# module.detections.elasticstack_kibana_security_detection_rule.this["some-uid"]
ADDRESS = re.compile(r'^(?P<prefix>.*\.)?(?P<resource>[a-z_]+)\.this\["(?P<key>[^"]+)"\]$')


class Kibana:
    def __init__(self, cluster: str):
        prefix = cluster.upper()
        self.base = os.environ[f"{prefix}_KIBANA_URL"].rstrip("/")
        self.space = os.environ.get(f"{prefix}_SPACE_ID", "default")
        self.session = requests.Session()
        self.session.headers.update({"kbn-xsrf": "true"})
        self.session.auth = (
            os.environ[f"{prefix}_KIBANA_USERNAME"],
            os.environ[f"{prefix}_KIBANA_PASSWORD"],
        )
        self.session.verify = (
            os.environ.get(f"{prefix}_VERIFY_TLS", "true").lower() != "false"
        )

    def url(self, path: str) -> str:
        if self.space != "default":
            return f"{self.base}/s/{self.space}{path}"
        return f"{self.base}{path}"

    def rule_by_rule_id(self, rule_id: str) -> dict | None:
        response = self.session.get(
            self.url("/api/detection_engine/rules"),
            params={"rule_id": rule_id},
            timeout=30,
        )
        return response.json() if response.status_code == 200 else None

    def exception_list(self, list_id: str, namespace: str = "single") -> dict | None:
        response = self.session.get(
            self.url("/api/exception_lists"),
            params={"list_id": list_id, "namespace_type": namespace},
            timeout=30,
        )
        return response.json() if response.status_code == 200 else None

    def exception_item(self, item_id: str, namespace: str = "single") -> dict | None:
        response = self.session.get(
            self.url("/api/exception_lists/items"),
            params={"item_id": item_id, "namespace_type": namespace},
            timeout=30,
        )
        return response.json() if response.status_code == 200 else None


def load_defaults(rules_dir: Path) -> dict:
    path = rules_dir / "_defaults.yaml"
    return yaml.safe_load(path.read_text()) if path.exists() else {}


def repo_rules(rules_dir: Path, cluster: str, namespace: uuid.UUID) -> dict[str, str]:
    """uid -> rule_id, for rules this cluster is supposed to have."""
    defaults = load_defaults(rules_dir)
    wanted = {}

    for path in sorted(rules_dir.rglob("*.yaml")):
        if path.name.startswith("_"):
            continue
        rule = {**defaults, **yaml.safe_load(path.read_text())}
        if cluster not in rule.get("targets", ["dc", "dr"]):
            continue
        # Must mirror rules.tf: a pinned rule_id wins over the derived one.
        wanted[rule["uid"]] = rule.get("rule_id") or str(
            uuid.uuid5(namespace, rule["uid"])
        )

    return wanted


def repo_exceptions(exceptions_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    """(uid -> list_id, "listuid/itemuid" -> item_id)"""
    lists, items = {}, {}
    for path in sorted(exceptions_dir.rglob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        lists[doc["uid"]] = doc["list_id"]
        for item in doc.get("items", []) or []:
            items[f"{doc['uid']}/{item['uid']}"] = item["item_id"]
    return lists, items


def terraform(tf_dir: Path, *args: str, capture: bool = True):
    return subprocess.run(
        ["terraform", f"-chdir={tf_dir}", *args],
        capture_output=capture,
        text=True,
    )


def state_keys(tf_dir: Path) -> dict[str, set[str]]:
    """resource type -> set of for_each keys currently in state."""
    result = terraform(tf_dir, "state", "list")
    if result.returncode != 0:
        # An empty or uninitialised state is not an error; there is simply
        # nothing in it yet.
        return {}

    found: dict[str, set[str]] = {}
    for line in result.stdout.splitlines():
        match = ADDRESS.match(line.strip())
        if match:
            found.setdefault(match.group("resource"), set()).add(match.group("key"))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--rules-dir", default="detections/rules")
    parser.add_argument("--exceptions-dir", default="detections/exceptions")
    parser.add_argument("--tf-dir", default="terraform/deployments/detections")
    parser.add_argument("--var-file", help="Defaults to targets/vps-<cluster>.tfvars")
    parser.add_argument("--module-path", default="module.detections.")
    parser.add_argument(
        "--namespace",
        default=os.environ.get(
            "RULE_ID_NAMESPACE", "1b671a64-40d5-491e-99b0-da01ff1f3341"
        ),
    )
    parser.add_argument("--apply", action="store_true", help="Actually import.")
    args = parser.parse_args()

    tf_dir = Path(args.tf_dir)
    var_file = args.var_file or f"targets/vps-{args.cluster}.tfvars"
    namespace = uuid.UUID(args.namespace)

    kibana = Kibana(args.cluster)
    in_state = state_keys(tf_dir)

    wanted_rules = repo_rules(Path(args.rules_dir), args.cluster, namespace)
    wanted_lists, wanted_items = repo_exceptions(Path(args.exceptions_dir))

    pending: list[tuple[str, str, str]] = []  # (resource, key, import id)

    # --- rules -------------------------------------------------------------
    for uid, rule_id in sorted(wanted_rules.items()):
        if uid in in_state.get(RULE_RESOURCE, set()):
            continue
        live = kibana.rule_by_rule_id(rule_id)
        if live:
            pending.append((RULE_RESOURCE, uid, f"{kibana.space}/{live['id']}"))
        # Not in Kibana either: plan will create it, which is correct.

    # --- exception lists ---------------------------------------------------
    for uid, list_id in sorted(wanted_lists.items()):
        if uid in in_state.get(LIST_RESOURCE, set()):
            continue
        live = kibana.exception_list(list_id)
        if live:
            pending.append((LIST_RESOURCE, uid, f"{kibana.space}/{live['id']}"))

    # --- exception items ---------------------------------------------------
    for key, item_id in sorted(wanted_items.items()):
        if key in in_state.get(ITEM_RESOURCE, set()):
            continue
        live = kibana.exception_item(item_id)
        if live:
            pending.append((ITEM_RESOURCE, key, f"{kibana.space}/{live['id']}"))

    if not pending:
        print(f"[{args.cluster}] state is consistent with Kibana, nothing to import")
        return 0

    print(f"[{args.cluster}] {len(pending)} object(s) exist in Kibana but not in state:")
    for resource, key, import_id in pending:
        print(f"  {key:<45} {resource.replace('elasticstack_kibana_security_', '')}")

    if not args.apply:
        print("\nRe-run with --apply to import these, or the next apply will "
              "fail with 409 rule_id already exists.")
        return 1

    failures = 0
    for resource, key, import_id in pending:
        address = f'{args.module_path}{resource}.this["{key}"]'
        print(f"\nimporting {key}")
        result = terraform(
            tf_dir, "import", f"-var-file={var_file}", address, import_id,
            capture=False,
        )
        if result.returncode != 0:
            print(f"  FAILED - import {address} {import_id}")
            failures += 1

    if failures:
        print(f"\n{failures} import(s) failed.")
        return 1

    print(f"\nImported {len(pending)} object(s) into {args.cluster} state.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
