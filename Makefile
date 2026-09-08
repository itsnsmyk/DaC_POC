CLUSTER ?= dc
TF      := terraform -chdir=terraform/deployments/detections

.PHONY: check lock init plan apply postcheck parity new-rule

check:
	python3 tools/precheck.py --rules-dir detections/rules --exceptions-dir detections/exceptions \
		--schema detections/schemas/rule.schema.json --lockfile detections/rules.lock.json

lock:
	python3 tools/precheck.py --update-lock

init:
	$(TF) init -reconfigure -backend-config=backends/$(CLUSTER).hcl

plan: check init
	$(TF) plan -var-file=targets/$(CLUSTER).tfvars -out=$(CLUSTER).tfplan
	$(TF) show -json $(CLUSTER).tfplan > plan-$(CLUSTER).json
	python3 tools/plan_guard.py plan-$(CLUSTER).json --max-destroy 3

apply:
	$(TF) apply $(CLUSTER).tfplan

postcheck:
	python3 tools/postcheck.py --cluster $(CLUSTER) --settle 120

parity:
	python3 tools/drift_compare.py --left dc --right dr --show-diff

# make new-rule UID=win-something-suspicious OS=windows
new-rule:
	@test -n "$(UID)" || (echo "UID= required"; exit 1)
	@sed -e "s/^uid:.*/uid: $(UID)/" rules/linux/curl_download_to_tmp.yaml \
		> rules/$(OS)/$(shell python3 -c "import sys;print('_'.join(w.capitalize() for w in '$(UID)'.split('-')))").yaml
	@echo "created rules/$(OS)/ - edit it, then: make check"

# make migrate INPUT=./old-rules
migrate:
	@test -n "$(INPUT)" || (echo "INPUT= required (dir of UUID.json, or an .ndjson export)"; exit 1)
	python3 tools/migrate_from_export.py --input $(INPUT) --dry-run
	@echo
	@read -p "Write these files? [y/N] " a; [ "$$a" = "y" ] || exit 1
	python3 tools/migrate_from_export.py --input $(INPUT) --out rules
	python3 tools/precheck.py --update-lock
