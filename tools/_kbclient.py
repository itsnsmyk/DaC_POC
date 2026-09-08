"""Minimal Kibana detection-engine client shared by the post-check scripts."""
import os
import urllib.parse

import requests


class Kibana:
    def __init__(self, base_url, space_id="default", verify=True,
                 username=None, password=None, api_key=None):
        self.base = base_url.rstrip("/")
        self.space_id = space_id
        self.verify = verify
        self.s = requests.Session()
        self.s.headers.update({"kbn-xsrf": "true", "Content-Type": "application/json"})
        if api_key:
            self.s.headers["Authorization"] = f"ApiKey {api_key}"
        elif username:
            self.s.auth = (username, password)

    @classmethod
    def from_env(cls, prefix):
        """prefix e.g. 'DC' -> DC_KIBANA_URL, DC_KIBANA_API_KEY, ..."""
        return cls(
            base_url=os.environ[f"{prefix}_KIBANA_URL"],
            space_id=os.environ.get(f"{prefix}_SPACE_ID", "default"),
            verify=os.environ.get(f"{prefix}_VERIFY_TLS", "true").lower() != "false",
            username=os.environ.get(f"{prefix}_KIBANA_USERNAME"),
            password=os.environ.get(f"{prefix}_KIBANA_PASSWORD"),
            api_key=os.environ.get(f"{prefix}_KIBANA_API_KEY"),
        )

    def _url(self, path):
        if self.space_id and self.space_id != "default":
            return f"{self.base}/s/{self.space_id}{path}"
        return f"{self.base}{path}"

    def get_rule(self, rule_id):
        r = self.s.get(self._url("/api/detection_engine/rules"),
                       params={"rule_id": rule_id}, verify=self.verify, timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def find_rules(self, kql_filter=None, per_page=100):
        """Page through _find, optionally filtered (e.g. by a Terraform tag)."""
        page, out = 1, []
        while True:
            params = {"page": page, "per_page": per_page, "sort_field": "name",
                      "sort_order": "asc"}
            if kql_filter:
                params["filter"] = kql_filter
            r = self.s.get(self._url("/api/detection_engine/rules/_find"),
                           params=params, verify=self.verify, timeout=60)
            r.raise_for_status()
            body = r.json()
            out.extend(body.get("data", []))
            if page * per_page >= body.get("total", 0):
                return out
            page += 1

    def get_exception_list(self, list_id, namespace_type="single"):
        r = self.s.get(self._url("/api/exception_lists"),
                       params={"list_id": list_id, "namespace_type": namespace_type},
                       verify=self.verify, timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def get_exception_items(self, list_id, namespace_type="single"):
        r = self.s.get(self._url("/api/exception_lists/items/_find"),
                       params={"list_id": list_id, "namespace_type": namespace_type,
                               "per_page": 100},
                       verify=self.verify, timeout=30)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json().get("data", [])
