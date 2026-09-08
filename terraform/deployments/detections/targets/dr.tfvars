cluster_role           = "dr"
kibana_endpoint        = "https://kibana-dr.internal.example.com:5601"
elasticsearch_endpoint = "https://es-dr.internal.example.com:9200"
space_id               = "default"
kibana_ca_certs        = ["/etc/ssl/certs/internal-ca.pem"]

# Connector IDs differ per cluster - that is exactly why rules reference
# connectors by logical name and resolve here.
connector_ids = {
  soc_pagerduty = { id = "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a", action_type_id = ".server-log" }
  soc_slack     = { id = "c1d2e3f4-a5b6-4708-9c8d-7e6f5a4b3c2d", action_type_id = ".server-log" }
}

tag_prefix = ["Managed: Terraform", "Site: DR"]

# Optional: keep DR rules deployed but dormant so they don't double-alert
# while DC is primary. Flip to null (or remove) for active/active.
# enabled_override = false
