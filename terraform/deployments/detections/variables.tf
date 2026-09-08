variable "cluster_role" { type = string }
variable "kibana_endpoint" { type = string }
variable "elasticsearch_endpoint" { type = string }

variable "kibana_ca_certs" {
  type    = list(string)
  default = null
}

variable "space_id" {
  type    = string
  default = "default"
}

variable "rule_id_namespace" {
  type        = string
  description = "MUST be identical for every cluster in the estate."
  default     = "78d5ddf7-7d5f-4e40-a98e-6b5e8dcee74d"
}

variable "connector_ids" {
  type = map(object({
    id             = string
    action_type_id = string
  }))
  default = {}
}

variable "enabled_override" {
  type    = bool
  default = null
}

variable "tag_prefix" {
  type    = list(string)
  default = ["Managed: Terraform"]
}
