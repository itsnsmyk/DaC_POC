terraform {
  required_version = ">= 1.5.0"

  required_providers {
    elasticstack = {
      source  = "elastic/elasticstack"
      version = "0.16.4"
    }
  }

  # Backend is intentionally partial. Jenkins supplies the rest:
  #   terraform init -reconfigure -backend-config=backends/${CLUSTER}.hcl
  backend "s3" {}
}

provider "elasticstack" {
  kibana {
    endpoints = [var.kibana_endpoint]
    # Credentials come from KIBANA_USERNAME / KIBANA_PASSWORD (or KIBANA_API_KEY
    # on builds that support it). Never put them in tfvars.
    ca_certs = var.kibana_ca_certs
    insecure = false
  }

  elasticsearch {
    endpoints = [var.elasticsearch_endpoint]
  }
}

module "detections" {
  source = "../../modules/detections"

  rules_dir      = "${path.root}/../../../detections/rules"
  exceptions_dir = "${path.root}/../../../detections/exceptions"

  cluster_role      = var.cluster_role
  space_id          = var.space_id
  rule_id_namespace = var.rule_id_namespace
  connector_ids     = var.connector_ids
  enabled_override  = var.enabled_override
  tag_prefix        = var.tag_prefix
}
