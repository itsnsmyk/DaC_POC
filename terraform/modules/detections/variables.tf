variable "rules_dir" {
  type        = string
  description = "Absolute or module-relative path to the rules/ directory."
}

variable "exceptions_dir" {
  type        = string
  description = "Absolute or module-relative path to the exceptions/ directory."
}

variable "cluster_role" {
  type        = string
  description = "Logical name of the cluster being targeted (dc, dr, dev, ...). Matched against each rule's `targets` list."

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.cluster_role))
    error_message = "cluster_role must be lowercase alphanumeric with hyphens."
  }
}

variable "space_id" {
  type        = string
  description = "Kibana space that rules and exception lists are created in."
  default     = "default"
}

variable "rule_id_namespace" {
  type        = string
  description = <<-EOT
    UUIDv5 namespace used to derive each rule's stable rule_id from its uid.
    MUST be identical across DC, DR and every other cluster - this is what makes
    the same logical rule carry the same rule_id everywhere. Generate once with
    `uuidgen` and never change it: changing it recreates every rule.
  EOT
  default     = "78d5ddf7-7d5f-4e40-a98e-6b5e8dcee74d"
}

variable "connector_ids" {
  type        = map(string)
  description = "Maps the logical connector name used in rule YAML (e.g. soc_pagerduty) to the real connector ID on THIS cluster."
  default     = {}
}

variable "enabled_override" {
  type        = bool
  description = "When set, forces enabled=<value> on every rule regardless of YAML. Use false on DR if you want rules present but dormant."
  default     = null
}

variable "tag_prefix" {
  type        = list(string)
  description = "Tags appended to every rule, e.g. [\"Managed: Terraform\", \"Cluster: dc\"]. Makes reconciliation queries trivial."
  default     = ["Managed: Terraform"]
}
