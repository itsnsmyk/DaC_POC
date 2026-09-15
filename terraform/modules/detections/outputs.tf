output "rule_index" {
  description = "uid -> {rule_id, kibana_id, name, enabled}. Consumed by the post-check script."
  value = {
    for uid, r in elasticstack_kibana_security_detection_rule.this : uid => {
      rule_id   = r.rule_id
      kibana_id = r.id
      name      = r.name
      enabled   = r.enabled
      type      = r.type
      severity  = r.severity
    }
  }
}

output "rule_count" {
  description = "Number of rules managed on this cluster."
  value       = length(local.rules)
}

output "skipped_rules" {
  description = "Rules present in the repo but not targeted at this cluster."
  value       = sort(setsubtract(keys(local.rules_all), keys(local.rules)))
}

output "exception_lists" {
  value = { for uid, l in elasticstack_kibana_security_exception_list.this : uid => l.list_id }
}
