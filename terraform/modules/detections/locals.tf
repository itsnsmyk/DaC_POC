locals {
  # ---------------------------------------------------------------------------
  # Load and merge. Defaults are shallow-merged under each rule, so a key set in
  # the rule file always wins.
  # ---------------------------------------------------------------------------
  defaults = yamldecode(file("${var.rules_dir}/_defaults.yaml"))

  rule_files = [
    for f in fileset(var.rules_dir, "**/*.yaml") : f
    if !startswith(basename(f), "_")
  ]

  rules_all = {
    for f in local.rule_files :
    yamldecode(file("${var.rules_dir}/${f}")).uid => merge(
      local.defaults,
      yamldecode(file("${var.rules_dir}/${f}")),
      { source_file = f }
    )
  }

  # Only rules that target this cluster.
  rules = {
    for uid, r in local.rules_all : uid => r
    if contains(try(r.targets, ["dc", "dr"]), var.cluster_role)
  }

  # ---------------------------------------------------------------------------
  # Exception lists (+ their items, flattened so each item is its own resource).
  # ---------------------------------------------------------------------------
  exception_files = fileset(var.exceptions_dir, "**/*.yaml")

  exception_lists = {
    for f in local.exception_files :
    yamldecode(file("${var.exceptions_dir}/${f}")).uid => yamldecode(file("${var.exceptions_dir}/${f}"))
  }

  exception_items = {
    for pair in flatten([
      for list_uid, l in local.exception_lists : [
        for item in try(l.items, []) : {
          key      = "${list_uid}/${item.uid}"
          list_uid = list_uid
          item     = item
        }
      ]
    ]) : pair.key => pair
  }
}
