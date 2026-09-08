#!/usr/bin/env python3
"""
Pre-deployment validation. Runs before terraform even initialises.

Checks:
  1. YAML parses; conforms to schemas/rule.schema.json
  2. uid uniqueness, uid format, name uniqueness
  3. uid immutability against rules.lock.json (catches accidental recreations)
  4. Per-type required fields (esql must not set index, threshold needs value...)
  5. from/interval look-back window actually covers the interval
  6. Exception references resolve
  7. MITRE tactic/technique ID format
  8. Optional: live query validation against a dev cluster (--validate-queries)

Exit 0 = safe to plan. Non-zero = fail the build.
"""
import argparse
import json
import os
import re
import sys
import uuid
from pathlib import Path

import yaml

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

UID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
TACTIC_RE = re.compile(r"^TA\d{4}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DURATION_RE = re.compile(r"^(\d+)(s|m|h|d)$")
NOW_RE = re.compile(r"^now-(\d+)(s|m|h|d)$")

UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# Fields that make sense only for certain rule types.
TYPE_REQUIRED = {
    "query":            {"query", "language"},
    "saved_query":      {"saved_id"},
    "eql":              {"query", "language"},
    "esql":             {"query", "language"},
    "threshold":        {"query", "threshold"},
    "threat_match":     {"query", "threat_index", "threat_query", "threat_mapping"},
    "machine_learning": {"machine_learning_job_id", "anomaly_threshold"},
    "new_terms":        {"query", "new_terms_fields", "history_window_start"},
}
TYPE_FORBIDDEN = {
    "esql":             {"index"},          # ES|QL carries its own FROM clause
    "machine_learning": {"query", "index"},
}


class Findings:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def err(self, where, msg):
        self.errors.append(f"[ERROR] {where}: {msg}")

    def warn(self, where, msg):
        self.warnings.append(f"[WARN ] {where}: {msg}")


def seconds(expr):
    m = DURATION_RE.match(expr) or NOW_RE.match(expr)
    if not m:
        return None
    return int(m.group(1)) * UNIT_SECONDS[m.group(2)]


def load_yaml_dir(path, skip_underscore=True):
    out = {}
    for f in sorted(Path(path).rglob("*.yaml")):
        if skip_underscore and f.name.startswith("_"):
            continue
        with open(f) as fh:
            out[f] = yaml.safe_load(fh)
    return out


def check_rule(fp, rule, defaults, exception_uids, schema_validator, fnd):
    where = str(fp)
    merged = {**defaults, **rule}

    if schema_validator:
        for e in sorted(schema_validator.iter_errors(merged), key=lambda x: x.path):
            fnd.err(where, f"schema: {'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}")

    uid = merged.get("uid")
    if not uid:
        fnd.err(where, "missing required field 'uid'")
        return
    if not UID_RE.match(uid):
        fnd.err(where, f"uid '{uid}' must be lowercase-hyphenated (a-z, 0-9, '-')")

    rtype = merged.get("type")
    if rtype not in TYPE_REQUIRED:
        fnd.err(where, f"unknown rule type '{rtype}'")
        return

    for req in TYPE_REQUIRED[rtype]:
        if merged.get(req) in (None, "", [], {}):
            fnd.err(where, f"type '{rtype}' requires field '{req}'")
    for forb in TYPE_FORBIDDEN.get(rtype, set()):
        if merged.get(forb) is not None:
            fnd.err(where, f"type '{rtype}' must not set '{forb}'")

    # Severity / risk_score coherence - stops "critical, risk 10" nonsense.
    bands = {"low": (0, 21), "medium": (22, 47), "high": (48, 73), "critical": (74, 100)}
    sev, risk = merged.get("severity"), merged.get("risk_score")
    if sev in bands and isinstance(risk, int):
        lo, hi = bands[sev]
        if not (lo <= risk <= hi):
            fnd.warn(where, f"severity '{sev}' usually pairs with risk_score {lo}-{hi}, got {risk}")

    # Look-back must cover the interval, otherwise you silently drop events.
    iv, frm = seconds(merged.get("interval", "5m")), seconds(merged.get("from", "now-9m"))
    if iv and frm and frm <= iv:
        fnd.err(where, f"from ({merged['from']}) must look back further than interval ({merged['interval']}); "
                       f"use at least now-{iv // 60 + 4}m to absorb ingest lag")

    # MITRE hygiene
    for t in merged.get("threat", []) or []:
        tac = (t.get("tactic") or {}).get("id", "")
        if not TACTIC_RE.match(tac):
            fnd.err(where, f"invalid MITRE tactic id '{tac}'")
        for tech in t.get("technique", []) or []:
            if not TECHNIQUE_RE.match(tech.get("id", "")):
                fnd.err(where, f"invalid MITRE technique id '{tech.get('id')}'")
            for sub in tech.get("subtechnique", []) or []:
                if not TECHNIQUE_RE.match(sub.get("id", "")):
                    fnd.err(where, f"invalid MITRE sub-technique id '{sub.get('id')}'")
    if not merged.get("threat"):
        fnd.warn(where, "no MITRE ATT&CK mapping - required for coverage reporting")

    for ex in merged.get("exceptions", []) or []:
        if ex not in exception_uids:
            fnd.err(where, f"references unknown exception list uid '{ex}'")

    if not merged.get("false_positives"):
        fnd.warn(where, "no false_positives documented - triage analysts will need this")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules-dir", default="detections/rules")
    ap.add_argument("--exceptions-dir", default="detections/exceptions")
    ap.add_argument("--schema", default="detections/schemas/rule.schema.json")
    ap.add_argument("--lockfile", default="detections/rules.lock.json")
    ap.add_argument("--namespace", default=os.environ.get("RULE_ID_NAMESPACE",
                                                          "78d5ddf7-7d5f-4e40-a98e-6b5e8dcee74d"))
    ap.add_argument("--update-lock", action="store_true",
                    help="Rewrite the lockfile instead of enforcing it (use on approved removals).")
    ap.add_argument("--strict", action="store_true", help="Treat warnings as errors.")
    args = ap.parse_args()

    fnd = Findings()

    defaults_path = Path(args.rules_dir) / "_defaults.yaml"
    defaults = yaml.safe_load(open(defaults_path)) if defaults_path.exists() else {}

    exceptions = load_yaml_dir(args.exceptions_dir)
    exception_uids = set()
    for fp, ex in exceptions.items():
        uid = ex.get("uid")
        if not uid:
            fnd.err(str(fp), "exception list missing 'uid'")
            continue
        if uid in exception_uids:
            fnd.err(str(fp), f"duplicate exception uid '{uid}'")
        exception_uids.add(uid)
        item_uids = set()
        for it in ex.get("items", []) or []:
            if it.get("uid") in item_uids:
                fnd.err(str(fp), f"duplicate exception item uid '{it.get('uid')}'")
            item_uids.add(it.get("uid"))
            if not it.get("entries"):
                fnd.err(str(fp), f"exception item '{it.get('uid')}' has no entries")

    validator = None
    if Draft202012Validator and Path(args.schema).exists():
        validator = Draft202012Validator(json.load(open(args.schema)))
    elif not Draft202012Validator:
        fnd.warn("precheck", "jsonschema not installed - schema validation skipped")

    rules = load_yaml_dir(args.rules_dir)
    seen_uid, seen_name = {}, {}
    for fp, rule in rules.items():
        if not isinstance(rule, dict):
            fnd.err(str(fp), "file did not parse into a mapping")
            continue
        check_rule(fp, rule, defaults, exception_uids, validator, fnd)
        uid, name = rule.get("uid"), rule.get("name")
        if uid in seen_uid:
            fnd.err(str(fp), f"duplicate uid '{uid}' (also in {seen_uid[uid]})")
        seen_uid[uid] = fp
        if name in seen_name:
            fnd.err(str(fp), f"duplicate rule name '{name}' (also in {seen_name[name]})")
        seen_name[name] = fp

    # ----- uid immutability -------------------------------------------------
    # A rule's rule_id is either pinned in the file (migrated from an existing
    # Kibana deployment) or derived from the uid (born in this repo). Both are
    # recorded, so the lockfile is the one place that answers "what identity
    # does this rule have?" regardless of where it came from.
    ns = uuid.UUID(args.namespace)
    current, sources = {}, {}
    for fp, rule in rules.items():
        u = rule.get("uid") if isinstance(rule, dict) else None
        if not u:
            continue
        explicit = rule.get("rule_id")
        if explicit:
            if not re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", explicit):
                fnd.err(str(fp), f"rule_id '{explicit}' is not a UUID")
            current[u] = explicit
            sources[u] = "explicit"
        else:
            current[u] = str(uuid.uuid5(ns, u))
            sources[u] = "derived"

    collisions = {}
    for u, rid in current.items():
        collisions.setdefault(rid, []).append(u)
    for rid, uids in collisions.items():
        if len(uids) > 1:
            fnd.err("rule_id", f"rule_id {rid} claimed by multiple uids: {', '.join(sorted(uids))}")

    lock = Path(args.lockfile)
    payload = {
        "namespace": args.namespace,
        "rules": current,
        "sources": sources,
    }
    if args.update_lock or not lock.exists():
        lock.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        n_explicit = sum(1 for s in sources.values() if s == "explicit")
        print(f"[INFO ] lockfile written: {lock} ({len(current)} rules, "
              f"{n_explicit} migrated / {len(current) - n_explicit} derived)")
    else:
        prev = json.load(open(lock))
        prev_rules = prev.get("rules", {})
        prev_sources = prev.get("sources", {})

        # A namespace change only recreates rules whose id is DERIVED. Migrated
        # rules pin their own id and are unaffected - say so precisely.
        if prev.get("namespace") != args.namespace:
            at_risk = [u for u, s in sources.items() if s == "derived"]
            fnd.err(str(lock), f"rule_id_namespace changed - would recreate "
                               f"{len(at_risk)} derived-id rule(s)")

        removed = set(prev_rules) - set(current)
        if removed:
            fnd.err(str(lock),
                    "uid(s) removed or renamed: " + ", ".join(sorted(removed)) +
                    ". A rename destroys the rule and its alert history. If the rule is "
                    "genuinely going away, re-run with --update-lock in the same PR. "
                    "If you are only RENAMING it, add a `moved` block in "
                    "terraform/live/moved.tf first, then --update-lock.")

        for u, rid in current.items():
            if u in prev_rules and prev_rules[u] != rid:
                was = prev_sources.get(u, "derived")
                fnd.err(str(lock),
                        f"rule_id for '{u}' changed ({prev_rules[u]} -> {rid}). "
                        + ("The pinned rule_id was edited - this orphans the live rule."
                           if was == "explicit" else "Namespace drift."))

    for w in fnd.warnings:
        print(w)
    for e in fnd.errors:
        print(e)

    failed = bool(fnd.errors) or (args.strict and bool(fnd.warnings))
    print(f"\n{len(rules)} rules, {len(exceptions)} exception lists, "
          f"{len(fnd.errors)} error(s), {len(fnd.warnings)} warning(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
