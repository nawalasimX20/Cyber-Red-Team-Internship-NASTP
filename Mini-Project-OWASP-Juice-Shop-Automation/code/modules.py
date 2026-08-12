"""
modules.py
One function per OWASP Top 10:2025 category. Every function returns a list of
result dicts with a consistent shape so main.py / report.py don't need to
know anything about what's inside a given category:

{
    "category": "A05:2025 - Injection",
    "test_name": "SQL injection - login bypass",
    "request": "POST /rest/user/login  body={'email': \"' OR 1=1--\", ...}",
    "evidence": "<short extract of the response that supports the verdict>",
    "result": "VULNERABLE" | "NOT TRIGGERED" | "INFO",
    "detail": "one line explaining what the test checked and why it matters",
}

Detection is signature/pattern based (same approach used in the DVWA tool
this project extends) - it looks for known success indicators in each
response rather than doing anything exploit-grade. False negatives are
possible; see the report's Limitations section.
"""

import json
import base64


def _mk(category, test_name, request, evidence, result, detail):
    return {
        "category": category,
        "test_name": test_name,
        "request": request,
        "evidence": (evidence or "")[:300],
        "result": result,
        "detail": detail,
    }


# ---------------------------------------------------------------------
# A01:2025 - Broken Access Control
# ---------------------------------------------------------------------
def test_broken_access_control(client):
    cat = "A01:2025 - Broken Access Control"
    results = []

    # 1. IDOR - walk basket IDs that don't belong to the current user
    for basket_id in (1, 2, 3):
        resp = client.get(f"/rest/basket/{basket_id}", note="IDOR probe on /rest/basket/{id}")
        vulnerable = resp.status_code == 200 and str(basket_id) not in (client.token or "")
        results.append(_mk(
            cat, f"IDOR - read basket #{basket_id} belonging to another user",
            f"GET /rest/basket/{basket_id}",
            resp.text,
            "VULNERABLE" if resp.status_code == 200 else "NOT TRIGGERED",
            "Checks whether an authenticated user can read someone else's shopping basket "
            "simply by changing the numeric ID in the URL.",
        ))

    # 2. Direct access to an admin-only endpoint without an admin role
    resp = client.get("/rest/admin/application-version", note="Access admin endpoint as low-priv user")
    results.append(_mk(
        cat, "Forced browsing - admin endpoint reachable by any authenticated user",
        "GET /rest/admin/application-version",
        resp.text,
        "VULNERABLE" if resp.status_code == 200 else "NOT TRIGGERED",
        "Admin-only functionality should reject requests from non-admin accounts (403), "
        "not silently serve the data.",
    ))
    return results


# ---------------------------------------------------------------------
# A02:2025 - Security Misconfiguration
# ---------------------------------------------------------------------
def test_security_misconfiguration(client):
    cat = "A02:2025 - Security Misconfiguration"
    results = []

    # 1. Missing security headers
    resp = client.get("/", note="Inspect response headers on the home page")
    missing = [h for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options")
               if h not in resp.headers]
    results.append(_mk(
        cat, "Missing hardening HTTP headers",
        "GET /",
        f"Missing: {', '.join(missing) if missing else 'none'}",
        "VULNERABLE" if missing else "NOT TRIGGERED",
        "Checks for common defensive headers (CSP, X-Frame-Options, X-Content-Type-Options).",
    ))

    # 2. Exposed developer / debug endpoint
    resp = client.get("/ftp/", note="Check for exposed FTP-style file listing")
    results.append(_mk(
        cat, "Exposed file listing endpoint",
        "GET /ftp/",
        resp.text,
        "VULNERABLE" if resp.status_code == 200 and "<a href" in resp.text.lower() else "NOT TRIGGERED",
        "Looks for a directory-listing style endpoint left reachable in the deployed app.",
    ))
    return results


# ---------------------------------------------------------------------
# A03:2025 - Software Supply Chain Failures
# ---------------------------------------------------------------------
def test_software_supply_chain(client):
    cat = "A03:2025 - Software Supply Chain Failures"
    results = []

    resp = client.get("/", note="Fetch home page to inspect exposed client-side library versions")
    body = resp.text
    hints = []
    for lib in ("angular", "jquery", "bootstrap", "lodash"):
        if lib in body.lower():
            hints.append(lib)
    results.append(_mk(
        cat, "Client-side dependency fingerprinting",
        "GET /",
        f"Referenced libraries found in markup: {', '.join(hints) if hints else 'none detected'}",
        "INFO",
        "This only flags *which* front-end libraries are exposed for follow-up (e.g. checking "
        "them against a CVE database). It does not confirm a vulnerable version on its own - "
        "cross-reference with `npm audit` / a dependency-scanning tool such as OWASP "
        "Dependency-Check against the app's package.json for a real verdict.",
    ))

    resp2 = client.get("/package.json", note="Check whether package.json is directly exposed")
    results.append(_mk(
        cat, "Exposed package manifest",
        "GET /package.json",
        resp2.text,
        "VULNERABLE" if resp2.status_code == 200 else "NOT TRIGGERED",
        "A publicly reachable package.json/lockfile makes it trivial for an attacker to build "
        "a target list of exact dependency versions to search for known CVEs.",
    ))
    return results


# ---------------------------------------------------------------------
# A04:2025 - Cryptographic Failures
# ---------------------------------------------------------------------
def test_cryptographic_failures(client):
    cat = "A04:2025 - Cryptographic Failures"
    results = []

    # JWT is base64 - decode the header/payload (no crypto broken, just checking
    # what's stored and whether the algorithm is something weak like "none")
    if client.token:
        parts = client.token.split(".")
        alg_info = "unparseable"
        payload_info = ""
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            alg_info = header.get("alg", "?")
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            payload_info = json.dumps(payload)[:150]
        except Exception:
            pass
        results.append(_mk(
            cat, "JWT algorithm / claim inspection",
            "Decode session JWT (client-side, no request sent)",
            f"alg={alg_info}  payload={payload_info}",
            "VULNERABLE" if alg_info.lower() == "none" else "INFO",
            "Confirms the signing algorithm isn't 'none' and shows what claims (e.g. role, "
            "email) are stored in a token that's only base64-encoded, not encrypted - anyone "
            "who intercepts it can read those fields as plain text.",
        ))

    # Login over the current scheme - flag if the base_url is plain HTTP
    results.append(_mk(
        cat, "Transport encryption check",
        f"Scheme used for {client.base_url}",
        client.base_url,
        "VULNERABLE" if client.base_url.startswith("http://") else "NOT TRIGGERED",
        "Credentials and session tokens sent over plain HTTP can be captured by anyone on the "
        "network path. Expected on a local Docker test instance - flagged here as it would be "
        "a real finding in production.",
    ))
    return results


# ---------------------------------------------------------------------
# A05:2025 - Injection
# ---------------------------------------------------------------------
def test_injection(client):
    cat = "A05:2025 - Injection"
    results = []

    # 1. SQL injection login bypass
    payload = {"email": "' OR 1=1--", "password": "anything"}
    resp = client.post("/rest/user/login", note="SQLi login-bypass attempt", json=payload)
    success = resp.status_code == 200 and "authentication" in resp.text
    results.append(_mk(
        cat, "SQL injection - authentication bypass",
        f"POST /rest/user/login body={payload}",
        resp.text,
        "VULNERABLE" if success else "NOT TRIGGERED",
        "Classic ' OR 1=1-- payload in the email field. Success means the login query is "
        "built with unsanitized string concatenation.",
    ))

    # 2. Reflected XSS via search
    xss_payload = "<script>alert(1)</script>"
    resp2 = client.get("/rest/products/search", note="Reflected XSS probe via search endpoint",
                        params={"q": xss_payload})
    reflected = xss_payload in resp2.text
    results.append(_mk(
        cat, "Reflected XSS - product search",
        f"GET /rest/products/search?q={xss_payload}",
        resp2.text,
        "VULNERABLE" if reflected else "NOT TRIGGERED",
        "Checks whether a raw <script> tag sent as a search term is echoed back unescaped in "
        "the JSON/HTML response.",
    ))
    return results


# ---------------------------------------------------------------------
# A06:2025 - Insecure Design
# ---------------------------------------------------------------------
def test_insecure_design(client):
    cat = "A06:2025 - Insecure Design"
    results = []

    # Business-logic flaw: negative quantity / basket item manipulation
    payload = {"ProductId": 1, "BasketId": "1", "quantity": -5}
    resp = client.post("/api/BasketItems/", note="Add basket item with negative quantity",
                        json=payload)
    results.append(_mk(
        cat, "Negative-quantity basket manipulation",
        f"POST /api/BasketItems/ body={payload}",
        resp.text,
        "VULNERABLE" if resp.status_code in (200, 201) else "NOT TRIGGERED",
        "A well-designed basket should reject a negative quantity outright (it implies "
        "'refund me for items I never bought' if it reaches checkout). Accepting it points to "
        "missing business-logic validation, not just missing input sanitization.",
    ))
    return results


# ---------------------------------------------------------------------
# A07:2025 - Authentication Failures
# ---------------------------------------------------------------------
def test_authentication_failures(client):
    cat = "A07:2025 - Authentication Failures"
    results = []

    # Brute-force a known weak/default admin credential set (small, fixed list -
    # this is not a real brute-force attack, just a handful of common defaults)
    common_creds = [
        ("admin@juice-sh.op", "admin123"),
        ("admin@juice-sh.op", "admin"),
    ]
    hit = None
    attempts = []
    for email, pw in common_creds:
        resp = client.post("/rest/user/login", note=f"Credential-stuffing attempt {email}",
                            json={"email": email, "password": pw})
        attempts.append(f"{email}:{pw} -> {resp.status_code}")
        if resp.status_code == 200:
            hit = (email, pw)
            break

    results.append(_mk(
        cat, "Weak/default credential check",
        "POST /rest/user/login (small known-default list)",
        "; ".join(attempts),
        "VULNERABLE" if hit else "NOT TRIGGERED",
        "Tries a short, fixed list of commonly-used default credentials. A real engagement "
        "would rate-limit this heavily and get written authorization first - this tool caps it "
        "at two attempts for that reason.",
    ))

    # Password policy check via registration
    weak_pw = "1"
    resp2 = client.post("/api/Users/", note="Register account with a 1-character password",
                         json={"email": "policycheck@example.com", "password": weak_pw,
                               "passwordRepeat": weak_pw})
    results.append(_mk(
        cat, "Weak password policy",
        f"POST /api/Users/ password='{weak_pw}'",
        resp2.text,
        "VULNERABLE" if resp2.status_code in (200, 201) else "NOT TRIGGERED",
        "A 1-character password should be rejected by server-side policy, not just discouraged "
        "in the UI.",
    ))
    return results


# ---------------------------------------------------------------------
# A08:2025 - Software or Data Integrity Failures
# ---------------------------------------------------------------------
def test_software_data_integrity(client):
    cat = "A08:2025 - Software or Data Integrity Failures"
    results = []

    # JWT alg=none tampering - build a token with no signature and see if it's accepted
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps({"data": {"role": "admin"}}).encode()).decode().rstrip("=")
    forged = f"{header}.{body}."
    old_auth = client.session.headers.get("Authorization")
    client.session.headers.update({"Authorization": f"Bearer {forged}"})
    resp = client.get("/rest/user/whoami", note="Present alg=none forged JWT")
    if old_auth:
        client.session.headers.update({"Authorization": old_auth})
    else:
        client.session.headers.pop("Authorization", None)

    results.append(_mk(
        cat, "JWT integrity - alg=none tampering",
        "GET /rest/user/whoami with a self-signed, unsigned ('alg: none') JWT",
        resp.text,
        "VULNERABLE" if resp.status_code == 200 else "NOT TRIGGERED",
        "If the server accepts a token with no signature at all, it isn't actually verifying "
        "integrity - anyone can forge any claim (e.g. role: admin).",
    ))
    return results


# ---------------------------------------------------------------------
# A09:2025 - Security Logging and Alerting Failures
# ---------------------------------------------------------------------
def test_logging_and_alerting(client):
    cat = "A09:2025 - Security Logging and Alerting Failures"
    results = []
    results.append(_mk(
        cat, "Automated logging/alerting check - not applicable via HTTP",
        "N/A",
        "This category concerns server-side/infra behaviour (are failed logins, access-control "
        "violations, etc. actually logged and alerted on?).",
        "INFO",
        "Cannot be verified with black-box HTTP requests alone - it requires access to the "
        "application's or SIEM's logs. This module intentionally sends a burst of failed "
        "logins from the other modules; check the container/app logs manually to confirm "
        "whether they were recorded and whether any alert fired.",
    ))
    return results


# ---------------------------------------------------------------------
# A10:2025 - Mishandling of Exceptional Conditions
# ---------------------------------------------------------------------
def test_exceptional_conditions(client):
    cat = "A10:2025 - Mishandling of Exceptional Conditions"
    results = []

    # Malformed JSON body to a real endpoint
    resp = client.post(
        "/rest/user/login",
        note="Send malformed JSON body to trigger an unhandled parser error",
        data="{not valid json",
        headers={"Content-Type": "application/json"},
    )
    leaks_stack = any(k in resp.text.lower() for k in ("at ", "stacktrace", ".js:", "node_modules"))
    results.append(_mk(
        cat, "Verbose error / stack trace on malformed input",
        "POST /rest/user/login  body='{not valid json' (Content-Type: application/json)",
        resp.text,
        "VULNERABLE" if leaks_stack else "NOT TRIGGERED",
        "A malformed request should return a clean, generic error. A raw stack trace leaks "
        "file paths, framework internals and library versions that help an attacker plan "
        "further attacks.",
    ))

    # Unexpected data type on a numeric field
    resp2 = client.get("/rest/products/search", note="Send an array where a string query param is expected",
                        params={"q[]": "test"})
    results.append(_mk(
        cat, "Unexpected input type handling",
        "GET /rest/products/search?q[]=test",
        resp2.text,
        "VULNERABLE" if resp2.status_code == 500 else "NOT TRIGGERED",
        "A 500 response indicates an unhandled exception rather than a graceful validation "
        "error for the wrong parameter shape.",
    ))
    return results


# ---------------------------------------------------------------------
# Registry - maps the menu the user sees to the function that runs it
# ---------------------------------------------------------------------
CATEGORY_MODULES = {
    "A01": ("A01:2025 - Broken Access Control", test_broken_access_control),
    "A02": ("A02:2025 - Security Misconfiguration", test_security_misconfiguration),
    "A03": ("A03:2025 - Software Supply Chain Failures", test_software_supply_chain),
    "A04": ("A04:2025 - Cryptographic Failures", test_cryptographic_failures),
    "A05": ("A05:2025 - Injection", test_injection),
    "A06": ("A06:2025 - Insecure Design", test_insecure_design),
    "A07": ("A07:2025 - Authentication Failures", test_authentication_failures),
    "A08": ("A08:2025 - Software or Data Integrity Failures", test_software_data_integrity),
    "A09": ("A09:2025 - Security Logging and Alerting Failures", test_logging_and_alerting),
    "A10": ("A10:2025 - Mishandling of Exceptional Conditions", test_exceptional_conditions),
}
