cluster_role           = "dr"
kibana_endpoint        = "http://localhost:5601"
elasticsearch_endpoint = "https://localhost:9200"
space_id               = "dr"
connector_ids = {
  soc_pagerduty = { id = "8b026704-4cf5-46c7-b55c-31f8ef1e8d29", action_type_id = ".server-log" }
  soc_slack     = { id = "8b026704-4cf5-46c7-b55c-31f8ef1e8d29", action_type_id = ".server-log" }
}
tag_prefix = ["Managed: Terraform", "Site: VPS-DR"]
