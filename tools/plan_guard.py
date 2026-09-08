#!/usr/bin/env python3
"""
Guardrail on `terraform show -json plan.out`.

Terraform will happily delete 400 detection rules if someone deletes a directory.
This fails the build when a plan destroys or replaces more than the allowed
budget, and prints a human-readable summary keyed by rule uid.

    terraform plan -out=plan.out -var-file=envs/dc.tfvars
    terraform show -json plan.out > plan.json
    python3 scripts/plan_guard.py plan.json --max-destroy 3
"""
import argparse
import json
import re
import sys

UID_RE = re.compile(r'\["([^"]+)"\]$')


def uid_of(addr):
    m = UID_RE.search(addr)
    return m.group(1) if m else addr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("plan_json")
    ap.add_argument("--max-destroy", type=int, default=3)
    ap.add_argument("--max-replace", type=int, default=3)
    args = ap.parse_args()

    plan = json.load(open(args.plan_json))
    buckets = {"create": [], "update": [], "delete": [], "replace": [], "no-op": []}

    for rc in plan.get("resource_changes", []):
        actions = rc["change"]["actions"]
        if actions == ["no-op"]:
            key = "no-op"
        elif set(actions) >= {"delete", "create"}:
            key = "replace"
        elif actions == ["create"]:
            key = "create"
        elif actions == ["update"]:
            key = "update"
        elif actions == ["delete"]:
            key = "delete"
        else:
            key = "update"
        buckets[key].append((rc["address"], rc["type"]))

    for key in ("create", "update", "replace", "delete"):
        if not buckets[key]:
            continue
        print(f"\n{key.upper()} ({len(buckets[key])}):")
        for addr, rtype in sorted(buckets[key]):
            print(f"  - {uid_of(addr):<45} {rtype}")

    print(f"\nSummary: +{len(buckets['create'])} ~{len(buckets['update'])} "
          f"!{len(buckets['replace'])} -{len(buckets['delete'])} "
          f"(unchanged: {len(buckets['no-op'])})")

    failed = False
    if len(buckets["delete"]) > args.max_destroy:
        print(f"\nFAIL: plan destroys {len(buckets['delete'])} resources, "
              f"budget is {args.max_destroy}.")
        failed = True
    if len(buckets["replace"]) > args.max_replace:
        print(f"\nFAIL: plan replaces {len(buckets['replace'])} resources, "
              f"budget is {args.max_replace}. Replacement of a detection rule "
              f"destroys its alert history - check for a renamed uid.")
        failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
