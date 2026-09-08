cluster_role           = "dc"
kibana_endpoint        = "https://kibana-dc.internal.example.com:5601"
elasticsearch_endpoint = "https://es-dc.internal.example.com:9200"
space_id               = "default"
kibana_ca_certs        = ["/etc/ssl/certs/internal-ca.pem"]

connector_ids = {
  soc_pagerduty = "4a1f2b8c-0d3e-4f5a-9b6c-7d8e9f0a1b2c"
  soc_slack     = "b2c3d4e5-6f70-4819-a2b3-c4d5e6f70819"
}

tag_prefix = ["Managed: Terraform", "Site: DC"]
