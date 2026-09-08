# =============================================================================
# Renaming a rule's `uid`
#
# The FILENAME is cosmetic - rename it whenever you like, nothing happens.
# The `uid` is the Terraform for_each key, so changing it makes Terraform plan a
# destroy + create: the rule is deleted and recreated, losing its alert history
# (and, if the rule_id is pinned, colliding with the live rule on create).
#
# `moved` blocks tell Terraform "this is the same resource under a new key", so
# the plan becomes a no-op instead. Add the block, THEN change the uid in the
# YAML, THEN run `python3 scripts/precheck.py --update-lock`, all in one PR.
#
# Keep entries here for at least one release cycle after the rename has been
# applied to every cluster, then delete them.
# =============================================================================

# Example: renamed uid from `threshold-ioc-network` to
# `threshold-ioc-network-intrusion-detection`.
#
# moved {
#   from = module.detections.elasticstack_kibana_security_detection_rule.this["threshold-ioc-network"]
#   to   = module.detections.elasticstack_kibana_security_detection_rule.this["threshold-ioc-network-intrusion-detection"]
# }
