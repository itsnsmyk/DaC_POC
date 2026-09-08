#!/usr/bin/env python3
"""
DC vs DR parity check. The single most valuable post-check in a dual-cluster
setup: proves both sides converged on byte-identical detection logic.

Compares only Terraform-managed rules, normalising away per-cluster and
per-instance noise (internal id, timestamps, version, connector ids, site tags).

    python3 scripts/drift_compare.py --left dc --right dr
"""
import argparse
import hashlib
import json
import os
import sys

from _kbclient import Kibana

MANAGED_TAG = os.environ.get("MANAGED_TAG", "Managed: Terraform")

# Fields that legitimately differ between clusters.
IGNORE = {
    "id", "created_at", "created_by", "updated_at", "updated_by",
    "execution_summary", "version", "revision", "actions", "outcome",
    "meta", "immutable", "rule_source", "throttle",
}
# Tag prefixes that are cluster-specific by design.
IGNORE_TAG_PREFIXES = ("Site: ", "Cluster: ")


def normalise(rule):
    out = {}
    for k, v in rule.items():
        if k in IGNORE:
            continue
        if k == "tags":
            v = sorted(t for t in v if not t.startswith(IGNORE_TAG_PREFIXES))
        if k == "exceptions_list":
            # Keep list_id/type only - the internal `id` differs per cluster.
            v = sorted(({"list_id": e.get("list_id"),
                         "type": e.get("type"),
                         "namespace_type": e.get("namespace_type")}
                        for e in v or []), key=lambda e: e["list_id"] or "")
        if isinstance(v, list) and v and all(isinstance(i, str) for i in v):
            v = sorted(v)
        out[k] = v
    return out


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--left", default="dc")
    ap.add_argument("--right", default="dr")
    ap.add_argument("--show-diff", action="store_true",
                    help="Print the differing field values, not just field names.")
    args = ap.parse_args()

    kbl = Kibana.from_env(args.left.upper())
    kbr = Kibana.from_env(args.right.upper())
    flt = f'alert.attributes.tags:"{MANAGED_TAG}"'

    left = {r["rule_id"]: r for r in kbl.find_rules(kql_filter=flt)}
    right = {r["rule_id"]: r for r in kbr.find_rules(kql_filter=flt)}

    only_left = sorted(set(left) - set(right))
    only_right = sorted(set(right) - set(left))
    both = sorted(set(left) & set(right))

    drifted = []
    for rid in both:
        nl, nr = normalise(left[rid]), normalise(right[rid])
        if digest(nl) != digest(nr):
            fields = sorted(k for k in set(nl) | set(nr) if nl.get(k) != nr.get(k))
            drifted.append((rid, left[rid].get("name"), fields, nl, nr))

    print(f"{args.left.upper()}: {len(left)} managed rules   "
          f"{args.right.upper()}: {len(right)} managed rules   "
          f"in both: {len(both)}\n")

    for rid in only_left:
        print(f"[ERROR] only on {args.left.upper()}: {left[rid].get('name')} ({rid})")
    for rid in only_right:
        print(f"[ERROR] only on {args.right.upper()}: {right[rid].get('name')} ({rid})")
    for rid, name, fields, nl, nr in drifted:
        print(f"[ERROR] content drift: {name} ({rid}) -> {', '.join(fields)}")
        if args.show_diff:
            for f in fields:
                print(f"          {args.left}: {nl.get(f)!r}")
                print(f"          {args.right}: {nr.get(f)!r}")

    failed = bool(only_left or only_right or drifted)
    if not failed:
        print(f"PARITY OK - {len(both)} rules identical across "
              f"{args.left.upper()} and {args.right.upper()}")
    else:
        print(f"\nPARITY FAILED: {len(only_left)} left-only, {len(only_right)} "
              f"right-only, {len(drifted)} drifted")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
