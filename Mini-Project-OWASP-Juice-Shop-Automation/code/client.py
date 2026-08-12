"""
client.py
Thin wrapper around a requests.Session for talking to a local OWASP Juice Shop
instance. Handles: creating a disposable test account, logging in, storing the
JWT so every subsequent request is authenticated, and a couple of small
helpers that every test module needs (raw request logging, basket helpers).

This tool is built to run ONLY against a Juice Shop instance the tester owns
or has explicit permission to test (e.g. a local Docker container).
"""

import time
import json
import requests


class JuiceShopClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token = None
        self.email = None
        self.password = None
        self.log = []  # running list of {method, url, status, note} for the report

    # ---------------------------------------------------------------
    # low level helpers
    # ---------------------------------------------------------------
    def _record(self, method, url, resp, note=""):
        entry = {
            "method": method,
            "url": url,
            "status": getattr(resp, "status_code", None),
            "note": note,
        }
        self.log.append(entry)
        return entry

    def get(self, path, note="", **kwargs):
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, timeout=10, **kwargs)
        self._record("GET", url, resp, note)
        return resp

    def post(self, path, note="", **kwargs):
        url = f"{self.base_url}{path}"
        resp = self.session.post(url, timeout=10, **kwargs)
        self._record("POST", url, resp, note)
        return resp

    def put(self, path, note="", **kwargs):
        url = f"{self.base_url}{path}"
        resp = self.session.put(url, timeout=10, **kwargs)
        self._record("PUT", url, resp, note)
        return resp

    # ---------------------------------------------------------------
    # account setup
    # ---------------------------------------------------------------
    def register_test_account(self):
        """Creates a throwaway account so authenticated modules have a
        logged-in session to work with, then logs in and stores the JWT."""
        stamp = int(time.time())
        self.email = f"tester{stamp}@example.com"
        self.password = "TestPass123!"

        payload = {
            "email": self.email,
            "password": self.password,
            "passwordRepeat": self.password,
            "securityQuestion": None,
            "securityAnswer": None,
        }
        resp = self.post(
            "/api/Users/",
            note="Register throwaway test account",
            json=payload,
        )
        if resp.status_code not in (200, 201):
            return False, resp

        return self.login(self.email, self.password)

    def login(self, email, password):
        resp = self.post(
            "/rest/user/login",
            note=f"Login as {email}",
            json={"email": email, "password": password},
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                self.token = data.get("authentication", {}).get("token")
                if self.token:
                    self.session.headers.update(
                        {"Authorization": f"Bearer {self.token}"}
                    )
                    return True, resp
            except json.JSONDecodeError:
                pass
        return False, resp

    def is_authenticated(self):
        return self.token is not None
