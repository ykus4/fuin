"""
Client for communicating with the fuin key management server.
"""

import requests


class KeyServerClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["X-API-Key"] = api_key

    def register_apk(self, package_name: str, apk_key: bytes, apk_signature: str) -> str:
        """
        Register a packed APK with the server.
        Returns the app_id assigned by the server.
        """
        resp = self.session.post(
            f"{self.base_url}/apps",
            json={
                "package_name": package_name,
                "key": apk_key.hex(),
                "apk_signature": apk_signature,
            },
        )
        resp.raise_for_status()
        return resp.json()["app_id"]

    def revoke_apk(self, app_id: str) -> None:
        resp = self.session.delete(f"{self.base_url}/apps/{app_id}")
        resp.raise_for_status()

    def list_apps(self) -> list[dict]:
        resp = self.session.get(f"{self.base_url}/apps")
        resp.raise_for_status()
        return resp.json()
