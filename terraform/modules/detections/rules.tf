# =============================================================================
# The whole point of this file:
#
#   for_each = local.rules      -> keyed by human-readable uid
#   rule_id  = uuidv5(ns, uid)  -> deterministic, identical on DC and DR
#
# So `terraform state list` reads like:
#   module.detections.elasticstack_kibana_security_detection_rule.this["win-svc-account-interactive-login"]
#
# and `terraform apply -target=...this[\"win-rdp-bruteforce-threshold\"]` works
# without you ever looking up a UUID.
# =============================================================================

resource "elasticstack_kibana_security_detection_rule" "this" {
  for_each = local.rules

  space_id = var.space_id

  # Identity resolution, in priority order:
  #
  #   1. `rule_id:` written explicitly in the YAML  -> BROWNFIELD. Rules migrated
  #      from an existing Kibana deployment keep the rule_id they already have,
  #      so Terraform adopts them instead of creating duplicates.
  #   2. uuidv5(namespace, uid)                      -> GREENFIELD. New rules get
  #      a deterministic id derived from their human-readable uid, identical on
  #      DC and DR without any API lookup.
  #
  # Either way the *filename* and the *for_each key* are free to be readable.
  #
  # NOTE: confirm `rule_id` is settable on your provider build with
  #   terraform providers schema -json | jq '..|.elasticstack_kibana_security_detection_rule?|.block.attributes|keys'
  # If it is computed-only, delete this line and adopt existing rules with
  # `terraform import` instead (scripts/migrate_from_export.py emits the commands).
  rule_id = try(each.value.rule_id, uuidv5(var.rule_id_namespace, each.key))

  name        = each.value.name
  description = each.value.description
  type        = each.value.type
  enabled     = var.enabled_override != null ? var.enabled_override : try(each.value.enabled, true)

  severity   = each.value.severity
  risk_score = each.value.risk_score

  interval    = try(each.value.interval, "5m")
  from        = try(each.value.from, "now-9m")
  to          = try(each.value.to, "now")
  max_signals = try(each.value.max_signals, null)

  author  = try(each.value.author, null)
  license = try(each.value.license, null)

  # Provenance tags make "which rules does Terraform own?" answerable in Kibana.
  tags = concat(
    try(each.value.tags, []),
    var.tag_prefix,
    ["Cluster: ${var.cluster_role}", "Rule UID: ${each.key}"]
  )

  false_positives = try(each.value.false_positives, null)
  references      = try(each.value.references, null)
  note            = try(each.value.note, null)
  setup           = try(each.value.setup, null)

  # --- query surface: only the keys relevant to `type` are ever set ----------
  language = try(each.value.language, null)
  query    = try(each.value.query, null)
  index    = try(each.value.index, null)
  filters  = try(each.value.filters, null)

  # threshold rules
  threshold = try(each.value.threshold, null)

  # new_terms rules
  new_terms_fields    = try(each.value.new_terms_fields, null)
  history_window_start = try(each.value.history_window_start, null)

  # machine_learning rules
  machine_learning_job_id = try(each.value.machine_learning_job_id, null)
  anomaly_threshold       = try(each.value.anomaly_threshold, null)

  # threat_match rules
  threat_index         = try(each.value.threat_index, null)
  threat_query         = try(each.value.threat_query, null)
  threat_mapping       = try(each.value.threat_mapping, null)
  # unsupported by this provider version:
  # threat_language      = try(each.value.threat_language, null)
  threat_indicator_path = try(each.value.threat_indicator_path, null)

  # saved_query rules
  saved_id = try(each.value.saved_id, null)

  # --- field overrides ------------------------------------------------------
  rule_name_override  = try(each.value.rule_name_override, null)
  timestamp_override  = try(each.value.timestamp_override, null)
  building_block_type = try(each.value.building_block_type, null)
  investigation_fields = try(each.value.investigation_fields, null)

  threat = try(each.value.threat, null)

  # --- exceptions: logical uid -> resolved list handle ----------------------
  exceptions_list = [
    for ex_uid in try(each.value.exceptions, []) : {
      id             = elasticstack_kibana_security_exception_list.this[ex_uid].id
      list_id        = elasticstack_kibana_security_exception_list.this[ex_uid].list_id
      namespace_type = elasticstack_kibana_security_exception_list.this[ex_uid].namespace_type
      type           = elasticstack_kibana_security_exception_list.this[ex_uid].type
    }
  ]

  # --- actions: logical connector name -> per-cluster connector id -----------
  actions = [
    for a in try(each.value.actions, []) : {
      action_type_id = var.connector_ids[a.connector].action_type_id
      id             = var.connector_ids[a.connector].id
      group          = try(a.group, "default")
      params         = jsonencode(try(a.params, {}))
    }
  ]

  lifecycle {
    precondition {
      condition     = alltrue([for ex in try(each.value.exceptions, []) : contains(keys(local.exception_lists), ex)])
      error_message = "Rule '${each.key}' references an exception list uid that does not exist under exceptions/."
    }
    precondition {
      condition     = alltrue([for a in try(each.value.actions, []) : contains(keys(var.connector_ids), a.connector)])
      error_message = "Rule '${each.key}' references a connector not mapped in connector_ids for cluster '${var.cluster_role}'."
    }
  }
}
