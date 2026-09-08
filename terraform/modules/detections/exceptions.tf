resource "elasticstack_kibana_security_exception_list" "this" {
  for_each = local.exception_lists

  space_id       = var.space_id
  list_id        = each.value.list_id
  name           = each.value.name
  description    = each.value.description
  type           = try(each.value.type, "detection")
  namespace_type = try(each.value.namespace_type, "single")
  tags           = try(each.value.tags, null)
}

resource "elasticstack_kibana_security_exception_item" "this" {
  for_each = local.exception_items

  space_id       = var.space_id
  list_id        = elasticstack_kibana_security_exception_list.this[each.value.list_uid].list_id
  item_id        = each.value.item.item_id
  name           = each.value.item.name
  description    = each.value.item.description
  type           = try(each.value.item.type, "simple")
  namespace_type = try(each.value.item.namespace_type, "single")
  tags           = try(each.value.item.tags, null)
  entries        = each.value.item.entries
}
