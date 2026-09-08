cluster_role           = "dc"
kibana_endpoint        = "http://localhost:5601"
elasticsearch_endpoint = "https://localhost:9200"
space_id               = "default"
connector_ids = {
  soc_pagerduty = { id = "471e683c-8557-4702-ae77-7e8f6dc02c86", action_type_id = ".server-log" }
  soc_slack     = { id = "471e683c-8557-4702-ae77-7e8f6dc02c86", action_type_id = ".server-log" }
}
tag_prefix = ["Managed: Terraform", "Site: VPS-DC"]
