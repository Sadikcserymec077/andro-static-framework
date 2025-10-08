# mob_sf_client.py
"""
MobSF client helper.
Provides:
 - upload_apk(local_path) -> returns hash / scan_id used by MobSF
 - scan_apk(hash) -> triggers scan (best-effort)
 - get_report_json(hash) -> returns parsed JSON report
 - sample_report() -> demo report used if MobSF is unreachable
"""

import os
import time
import requests

class MobSFClient:
    def __init__(self, base_url=None, api_key=None):
        self.base_url = base_url.rstrip("/") if base_url else None
        self.api_key = api_key
        self.headers = {"Authorization": self.api_key} if self.api_key else {}
        # Minimal validation
        if not self.base_url or not self.api_key:
            # We'll allow initialization but methods will raise if called against MobSF.
            pass

    def _endpoint(self, path):
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def upload_apk(self, apk_path):
        """
        Upload APK to MobSF: POST /api/v1/upload
        Returns: hash string (or raises)
        """
        if not self.base_url or not self.api_key:
            raise Exception("MOBSF_URL or MOBSF_API_KEY not set")

        url = self._endpoint("/api/v1/upload")
        files = {"file": open(apk_path, "rb")}
        resp = requests.post(url, files=files, headers=self.headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        # MobSF usually returns 'hash' key
        mob_hash = data.get("hash") or data.get("scan_id") or data.get("file_name")
        if not mob_hash:
            raise Exception("Unexpected upload response: missing hash")
        return mob_hash

    def scan_apk(self, mob_hash):
        """
        Trigger scan if required. MobSF may auto-scan on upload.
        POST /api/v1/scan
        """
        if not self.base_url or not self.api_key:
            raise Exception("MOBSF_URL or MOBSF_API_KEY not set")
        url = self._endpoint("/api/v1/scan")
        payload = {"hash": mob_hash}
        resp = requests.post(url, json=payload, headers=self.headers, timeout=30)
        # Some MobSF versions may return 200 or 201. We'll ignore any small errors.
        if resp.status_code not in (200, 201):
            # not fatal: keep going
            return False
        return True

    def get_report_json(self, mob_hash):
        """
        GET /api/v1/report_json?hash=<mob_hash>
        Returns parsed JSON
        """
        if not self.base_url or not self.api_key:
            raise Exception("MOBSF_URL or MOBSF_API_KEY not set")
        url = self._endpoint(f"/api/v1/report_json")
        params = {"hash": mob_hash}
        resp = requests.get(url, params=params, headers=self.headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data

    def sample_report(self):
        """
        Return a demo sample report JSON for UI testing
        """
        return {
            "app_name": "Demo App",
            "package_name": "com.example.demo",
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_EXTERNAL_STORAGE"
            ],
            "manifest_issues": [
                {"title": "exported_activities", "description": "Activity exported without permission", "severity": "High"}
            ],
            "third_party": {
                "libraries": [
                    {"name": "com.squareup.okhttp3:okhttp:3.12.0", "risk": "Medium"},
                    {"name": "com.google.code.gson:gson:2.8.0", "risk": "Low"}
                ]
            },
            "code_analysis": {
                "issues": [
                    {"title": "Hardcoded API Key", "file": "app/src/main/java/com/example/ApiClient.java", "line": 42, "severity": "High", "mitigation": "Move keys to secure storage"},
                    {"title": "Insecure SSL Validation", "file": "app/src/main/java/com/example/Net.java", "line": 88, "severity": "Medium", "mitigation": "Use proper certificate validation"},
                    {"title": "Logging Sensitive Info", "file": "app/src/main/java/com/example/Auth.java", "line": 15, "severity": "Low", "mitigation": "Avoid logging tokens"}
                ]
            },
            "summary": {
                "high": 1,
                "medium": 1,
                "low": 1,
                "info": 0
            }
        }
