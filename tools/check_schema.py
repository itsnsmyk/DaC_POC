#!/usr/bin/env python3
"""Report every module attribute the provider does not accept.

terraform validate stops at the first bad argument, so fixing a schema mismatch
becomes one init-validate cycle per attribute. This lists them all at once.

    terraform -chdir=terraform/deployments/detections providers schema -json > /tmp/schema.json
    python3 tools/check_schema.py /tmp/schema.json [--fix]
"""
import json, re, sys
from pathlib import Path

META = {"count", "for_each", "provider", "depends_on", "lifecycle"}
HEADER = re.compile(r'^resource\s+"([^"]+)"')
ATTR = re.compile(r'^  ([a-z_][a-z0-9_]*)\s*[={]')

schema_path, fix = Path(sys.argv[1]), "--fix" in sys.argv
data = json.loads(schema_path.read_text())
known = {
    rtype: set(s["block"].get("attributes", {})) | set(s["block"].get("block_types", {}))
    for p in data.get("provider_schemas", {}).values()
    for rtype, s in p.get("resource_schemas", {}).items()
}

problems = 0
for tf in sorted(Path("terraform/modules/detections").glob("*.tf")):
    lines = tf.read_text().splitlines()
    current, depth, bad = None, 0, []
    for n, line in enumerate(lines, 1):
        if (h := HEADER.match(line)):
            current, depth = h.group(1), 1
            continue
        if current is None:
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            current = None
            continue
        if (m := ATTR.match(line)) and m.group(1) not in META:
            name = m.group(1)
            if name not in known.get(current, set()):
                bad.append((n, name, current))
    for n, name, rtype in bad:
        stem = name.split("_")[0]
        near = sorted(k for k in known.get(rtype, set()) if stem in k)[:4]
        print(f"{tf.name}:{n}  {name}" + (f"   near: {', '.join(near)}" if near else ""))
        problems += 1
    if bad and fix:
        for n, _, _ in bad:
            lines[n - 1] = f"  # unsupported by this provider version:\n  # {lines[n-1].strip()}"
        tf.write_text("\n".join(lines) + "\n")
        print(f"  -> commented out {len(bad)} line(s) in {tf}")

print(f"\n{problems} unsupported attribute(s)." if problems else "\nAll attributes exist in the provider schema.")
sys.exit(1 if problems and not fix else 0)
