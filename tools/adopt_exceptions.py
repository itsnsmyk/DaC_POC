#!/usr/bin/env python3
"""Adopt exception lists created in the Kibana UI into the repository.

Why exceptions need their own path
----------------------------------
Kibana has two kinds of exception list:

  * shared lists      (type: detection)    - reusable across rules
  * rule default lists (type: rule_default) - created implicitly by the
                                              "Add rule exception" button and
                                              bound to one rule

The second kind is the problem. An analyst clicks "Add rule exception", Kibana
silently creates a rule_default list and attaches it, and the detection is now
narrower than the reviewed version with nothing in git to show it. Terraform
does not manage that list, so plan reports no change.

This pulls those lists out and writes them as ordinary shared lists in
detections/exceptions/. Converting rule_default to a named shared list is
deliberate: a named list is reviewable, reusable, and syncs to DR, whereas a
rule_default list is invisible plumbing that only exists on one cluster.

    python3 tools/adopt_exceptions.py --cluster dc --list
    python3 tools/adopt_exceptions.py --cluster dc --all
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import requests
import yaml

MANAGED_TAG = os.environ.get("MANAGED_TAG", "Managed: Terraform")

# Fields Kibana owns on a list or item.
SERVER_OWNED = {
    "id", "created_at", "created_by", "updated_at", "updated_by",
    "tie_breaker_id", "_version", "version", "immutable", "list_id",
    "namespace_type", "type", "expire_time", "comments", "meta",
}


def slugify(text: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    return re.sub(r"-{2,}", "-", slug)[:80].strip("-")


def titlecase(text: str) -> str:
    cleaned = re.sub(r"[^\w\s-]", " ", text)
    parts = [p for p in re.split(r"[\s\-_]+", cleaned) if p]
    return "_".join(p if p.isupper() else p[:1].upper() + p[1:].lower() for p in parts)


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
        return f"{self.base}/s/{self.space}{path}" if self.space != "default" else f"{self.base}{path}"

    def get(self, path: str, **params):
        response = self.session.get(self.url(path), params=params, timeout=30)
        if not response.ok:
            raise SystemExit(f"{path} -> {response.status_code}: {response.text[:300]}")
        return response.json()

    def rules(self) -> list[dict]:
        out, page = [], 1
        while True:
            body = self.get("/api/detection_engine/rules/_find",
                            page=page, per_page=100,
                            sort_field="name", sort_order="asc")
            out.extend(body.get("data", []))
            if page * 100 >= body.get("total", 0):
                return out
            page += 1

    def list_items(self, list_id: str, namespace: str) -> list[dict]:
        body = self.get("/api/exception_lists/items/_find",
                        list_id=list_id, namespace_type=namespace, per_page=100)
        return body.get("data", [])

    def exception_list(self, list_id: str, namespace: str) -> dict:
        return self.get("/api/exception_lists",
                        list_id=list_id, namespace_type=namespace)


def repo_list_ids(exceptions_dir: Path) -> set[str]:
    ids = set()
    for path in exceptions_dir.rglob("*.yaml"):
        doc = yaml.safe_load(path.read_text())
        if doc and doc.get("list_id"):
            ids.add(doc["list_id"])
    return ids


def clean(record: dict) -> dict:
    return {k: v for k, v in record.items()
            if k not in SERVER_OWNED and v not in (None, "", [], {})}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--exceptions-dir", default="detections/exceptions")
    parser.add_argument("--list", action="store_true", help="Report only.")
    parser.add_argument("--all", action="store_true", help="Adopt everything undeclared.")
    parser.add_argument("--list-id", help="Adopt one specific list.")
    args = parser.parse_args()

    kibana = Kibana(args.cluster)
    exceptions_dir = Path(args.exceptions_dir)
    known = repo_list_ids(exceptions_dir)

    # Walk managed rules and collect every list attached to them.
    attached: dict[str, dict] = {}
    for rule in kibana.rules():
        if MANAGED_TAG not in (rule.get("tags") or []):
            continue
        for entry in rule.get("exceptions_list") or []:
            list_id = entry.get("list_id")
            if not list_id:
                continue
            attached.setdefault(list_id, {
                "list_id": list_id,
                "namespace_type": entry.get("namespace_type", "single"),
                "type": entry.get("type", "detection"),
                "rules": [],
            })
            attached[list_id]["rules"].append(rule["name"])

    undeclared = {lid: meta for lid, meta in attached.items() if lid not in known}

    if args.list or not (args.all or args.list_id):
        print(f"{len(attached)} exception list(s) attached to managed rules on "
              f"'{args.cluster}', {len(undeclared)} not in the repo:\n")
        for list_id, meta in sorted(undeclared.items()):
            items = kibana.list_items(list_id, meta["namespace_type"])
            print(f"  {list_id}")
            print(f"    kind      : {meta['type']}"
                  + ("   (created by the UI's 'Add rule exception')"
                     if meta["type"] == "rule_default" else ""))
            print(f"    used by   : {', '.join(meta['rules'])}")
            print(f"    items     : {len(items)}")
            for item in items:
                entries = "; ".join(
                    f"{e.get('field')} {e.get('operator')} {e.get('value', e.get('type'))}"
                    for e in item.get("entries", [])
                )
                print(f"      - {item.get('name')}: {entries}")
        if not undeclared:
            return 0
        print("\nAdopt with --all, or --list-id <id> for one.")
        return 1 if undeclared else 0

    targets = ({args.list_id: attached[args.list_id]}
               if args.list_id and args.list_id in attached
               else undeclared)
    if not targets:
        print("Nothing to adopt.")
        return 0

    exceptions_dir.mkdir(parents=True, exist_ok=True)
    for list_id, meta in sorted(targets.items()):
        remote = kibana.exception_list(list_id, meta["namespace_type"])
        items = kibana.list_items(list_id, meta["namespace_type"])

        name = remote.get("name") or list_id
        # A rule_default list is named after its rule and is not reusable.
        # Give it a real name so the file explains itself.
        if meta["type"] == "rule_default":
            name = f"{meta['rules'][0]} Exceptions"

        doc = {
            "uid": slugify(name),
            "list_id": list_id,
            "name": name,
            "description": remote.get("description") or f"Adopted from {args.cluster}.",
            # Shared, not rule_default: a named list is reviewable and syncs to DR.
            "type": "detection",
            "namespace_type": meta["namespace_type"],
        }
        if remote.get("tags"):
            doc["tags"] = remote["tags"]

        doc["items"] = []
        for item in items:
            entry = clean(item)
            entry["uid"] = slugify(item.get("name", item["item_id"]))
            entry["item_id"] = item["item_id"]
            entry["type"] = item.get("type", "simple")
            entry["namespace_type"] = item.get("namespace_type", "single")
            entry.setdefault("description", item.get("description") or entry["uid"])
            doc["items"].append(entry)

        path = exceptions_dir / (titlecase(name) + ".yaml")
        header = (
            f"# Adopted from the Kibana UI on cluster '{args.cluster}'.\n"
            f"# Originally a {meta['type']} list attached to: "
            f"{', '.join(meta['rules'])}\n"
        )
        if meta["type"] == "rule_default":
            header += (
                "# Converted to a shared list so it is reviewable and deploys to\n"
                "# every target, rather than existing only on the cluster where\n"
                "# someone clicked 'Add rule exception'.\n"
            )
        path.write_text(header + yaml.dump(doc, sort_keys=False, allow_unicode=True, width=4096))
        print(f"wrote {path}")
        print(f"  add to each rule that uses it:\n    exceptions:\n      - {doc['uid']}")
        for rule_name in meta["rules"]:
            print(f"      (used by: {rule_name})")

    print("\nNext:\n  python3 tools/precheck.py --update-lock"
          "\n  python3 tools/reconcile_state.py --cluster dc --apply"
          "\n  ./vps/02-run-pipeline.sh --plan-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
