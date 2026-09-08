cluster_role           = "dc"
kibana_endpoint        = "https://kibana-dc.internal.example.com:5601"
elasticsearch_endpoint = "https://es-dc.internal.example.com:9200"
space_id               = "default"
kibana_ca_certs        = ["/etc/ssl/certs/internal-ca.pem"]

connector_ids = {
  soc_pagerduty = { id = "4a1f2b8c-0d3e-4f5a-9b6c-7d8e9f0a1b2c", action_type_id = ".server-log" }
  soc_slack     = { id = "b2c3d4e5-6f70-4819-a2b3-c4d5e6f70819", action_type_id = ".server-log" }
}

tag_prefix = ["Managed: Terraform", "Site: DC"]
