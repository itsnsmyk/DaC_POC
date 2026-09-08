#!/usr/bin/env python3
"""
Post-apply verification against a single cluster.

Reads the repo (source of truth) rather than the Terraform state, so it catches
provider bugs and out-of-band edits, not just state drift.

  1. Every targeted rule exists at its derived rule_id
  2. name / type / severity / enabled / interval match the YAML
  3. Declared exception lists are attached and their items are present
  4. No rule left in a failed execution state after a settle window
  5. No orphan Terraform-tagged rules in Kibana that the repo no longer declares

    python3 scripts/postcheck.py --cluster dc --settle 90
"""
import argparse
import os
import sys
import time
import uuid
from pathlib import Path

import yaml

from _kbclient import Kibana

MANAGED_TAG = os.environ.get("MANAGED_TAG", "Managed: Terraform")


def load_rules(rules_dir, cluster):
    defaults_path = Path(rules_dir) / "_defaults.yaml"
    defaults = yaml.safe_load(open(defaults_path)) if defaults_path.exists() else {}
    out = {}
    for f in sorted(Path(rules_dir).rglob("*.yaml")):
        if f.name.startswith("_"):
            continue
        merged = {**defaults, **yaml.safe_load(open(f))}
        if cluster in merged.get("targets", ["dc", "dr"]):
            out[merged["uid"]] = merged
    return out


def load_exceptions(exceptions_dir):
    return {
        (e := yaml.safe_load(open(f)))["uid"]: e
        for f in sorted(Path(exceptions_dir).rglob("*.yaml"))
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", required=True, help="dc | dr | dev")
    ap.add_argument("--rules-dir", default="detections/rules")
    ap.add_argument("--exceptions-dir", default="detections/exceptions")
    ap.add_argument("--namespace", default=os.environ.get("RULE_ID_NAMESPACE",
                                                          "78d5ddf7-7d5f-4e40-a98e-6b5e8dcee74d"))
    ap.add_argument("--settle", type=int, default=0,
                    help="Seconds to wait before checking execution status.")
    ap.add_argument("--allow-orphans", action="store_true")
    args = ap.parse_args()

    kb = Kibana.from_env(args.cluster.upper())
    ns = uuid.UUID(args.namespace)

    expected = load_rules(args.rules_dir, args.cluster)
    exceptions = load_exceptions(args.exceptions_dir)
    errors, warnings = [], []

    print(f"Verifying {len(expected)} rules on cluster '{args.cluster}' "
          f"({kb.base}, space={kb.space_id})\n")

    for uid, want in sorted(expected.items()):
        # Must mirror rules.tf exactly: pinned rule_id wins, else derive from uid.
        rule_id = want.get("rule_id") or str(uuid.uuid5(ns, uid))
        got = kb.get_rule(rule_id)
        if got is None:
            errors.append(f"{uid}: MISSING (expected rule_id {rule_id})")
            continue

        for field in ("name", "type", "severity", "risk_score", "interval"):
            if field in want and got.get(field) != want[field]:
                errors.append(f"{uid}: {field} mismatch - repo={want[field]!r} "
                              f"kibana={got.get(field)!r}")

        want_enabled = want.get("enabled", True)
        if os.environ.get(f"{args.cluster.upper()}_ENABLED_OVERRIDE"):
            want_enabled = os.environ[f"{args.cluster.upper()}_ENABLED_OVERRIDE"].lower() == "true"
        if got.get("enabled") != want_enabled:
            errors.append(f"{uid}: enabled mismatch - repo={want_enabled} "
                          f"kibana={got.get('enabled')}")

        attached = {e.get("list_id") for e in got.get("exceptions_list", []) or []}
        for ex_uid in want.get("exceptions", []) or []:
            ex = exceptions.get(ex_uid, {})
            if ex.get("list_id") not in attached:
                errors.append(f"{uid}: exception list '{ex_uid}' "
                              f"({ex.get('list_id')}) not attached")

        print(f"  ok  {uid:<45} -> {rule_id}")

    # ----- exception list items -------------------------------------------
    referenced = {e for r in expected.values() for e in (r.get("exceptions") or [])}
    for ex_uid in sorted(referenced):
        ex = exceptions[ex_uid]
        remote = kb.get_exception_list(ex["list_id"], ex.get("namespace_type", "single"))
        if not remote:
            errors.append(f"exception list '{ex_uid}' missing on cluster")
            continue
        remote_items = {i["item_id"] for i in
                        kb.get_exception_items(ex["list_id"], ex.get("namespace_type", "single"))}
        for it in ex.get("items", []) or []:
            if it["item_id"] not in remote_items:
                errors.append(f"exception item '{it['item_id']}' "
                              f"missing from list '{ex_uid}'")

    # ----- execution health ------------------------------------------------
    if args.settle:
        print(f"\nWaiting {args.settle}s for rules to execute...")
        time.sleep(args.settle)

    managed = kb.find_rules(kql_filter=f'alert.attributes.tags:"{MANAGED_TAG}"')
    expected_ids = {r.get("rule_id") or str(uuid.uuid5(ns, u))
                    for u, r in expected.items()}

    for r in managed:
        summary = (r.get("execution_summary") or {}).get("last_execution") or {}
        status = summary.get("status")
        if status in ("failed", "partial failure"):
            msg = (summary.get("message") or "")[:180]
            target = errors if status == "failed" else warnings
            target.append(f"{r.get('name')}: execution status '{status}' - {msg}")

    orphans = [r for r in managed if r.get("rule_id") not in expected_ids]
    if orphans:
        line = ("orphan Terraform-tagged rules present on cluster (not declared "
                "for this target): " + ", ".join(sorted(r.get("name", "?") for r in orphans)))
        (warnings if args.allow_orphans else errors).append(line)

    print()
    for w in warnings:
        print(f"[WARN ] {w}")
    for e in errors:
        print(f"[ERROR] {e}")
    print(f"\n{len(expected)} expected, {len(managed)} managed on cluster, "
          f"{len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
