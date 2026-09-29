#!/usr/bin/env python3
"""Log into Princeton's Stellic via CAS + Duo and dump the Stellic session cookies.

Flow (plain HTTP, no browser):
  1. stellic.princeton.edu -> SAML -> fed.princeton.edu CAS login form (netid/password)
  2. CAS -> Duo Universal Prompt; its JSON API is used to send a Duo Push
  3. User approves on their phone, then presses Enter here
  4. Duo finalize -> CAS -> SAML POST back to Stellic; Stellic cookies are collected

Setup:
  pip install requests
"""

import argparse
import getpass
import html
import json
import re
import sys
import time
from urllib.parse import parse_qs, urljoin, urlparse

import requests

STELLIC_URL = "https://stellic.princeton.edu/"
CAS_HOST = "fed.princeton.edu"
DUO_HOST_SUFFIX = "duosecurity.com"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
)
BROWSER_FEATURES = json.dumps(
    {
        "touch_supported": False,
        "platform_authenticator_status": "unavailable",
        "webauthn_supported": False,
        "screen_resolution_height": 0,
        "screen_resolution_width": 0,
        "screen_color_depth": 0,
    },
    separators=(",", ":"),
)
# Compact JSON, exactly as the dashboard's XHR sends it, asking only for the
# "Semester Summary" card. Its content lists the current term's enrolled courses.
SEMESTER_SUMMARY_WIDGETS = json.dumps(
    [{"id": "planner:get_semester_summary", "widget_type": "card",
      "title": "Semester Summary", "endpoint": "planner:get_semester_summary"}],
    separators=(",", ":"),
)


class StellicLoginError(Exception):
    pass


def _host(url):
    return urlparse(url).hostname or ""


def _form_inputs(page_html):
    """Map name -> value for the <input> tags in an HTML page."""
    inputs = {}
    for tag in re.findall(r"<input\b[^>]*>", page_html):
        name = re.search(r'name="([^"]*)"', tag)
        value = re.search(r'value="([^"]*)"', tag)
        if name:
            inputs[html.unescape(name.group(1))] = (
                html.unescape(value.group(1)) if value else ""
            )
    return inputs


class StellicLogin:
    """Two-phase login: start() sends the Duo push, finish() collects cookies."""

    def __init__(self, netid, password, trust_browser=False, timeout=10):
        self.netid = netid
        self.password = password
        self.trust_browser = trust_browser
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self._duo_base = self._authkey = self._txid = None
        self._duo_headers = {}

    def start(self):
        """Submit netid/password to CAS and send the Duo push. Returns the push's device name."""
        r = self._get(STELLIC_URL)
        if _host(r.url) != CAS_HOST:
            raise StellicLoginError(f"Expected CAS login page, got {r.url}")

        form = _form_inputs(r.text)
        form.update(username=self.netid, password=self.password)
        # CAS answers a bad password with 401 and re-renders the form.
        r = self.session.post(r.url, data=form, timeout=self.timeout)
        if not _host(r.url).endswith(DUO_HOST_SUFFIX):
            raise StellicLoginError(
                f"CAS login failed: {self._cas_error(r.text) or r.url}"
            )

        # r.url is https://api-XXXX.duosecurity.com/prompt/<akey>?authkey=...&req_trace_group=...
        url = urlparse(r.url)
        query = parse_qs(url.query)
        self._duo_base = f"{url.scheme}://{url.netloc}{url.path}"
        self._authkey = query["authkey"][0]
        self._duo_headers = {
            "Referer": r.url,
            "X-Duo-Req-Trace-Group": query.get("req_trace_group", [""])[0],
        }

        self._duo("GET", "/auth/payload", params={"browser_features": BROWSER_FEATURES})
        evaluation = self._duo(
            "GET",
            "/pre_authn/evaluation",
            params={
                "browser_features": BROWSER_FEATURES,
                "local_trust_choice": "undecided",
            },
        )
        factors = evaluation["auth_factors_context"]["available_unified_auth_factors"][
            "factors"
        ]
        push = next((f for f in factors if f["factor_type"] == "push"), None)
        if push is None:
            raise StellicLoginError("No Duo Push device registered on this account")

        sent = self._duo(
            "POST",
            "/auth/factors/push/auth",
            json={"pkey": push["device_info"]["pkey"]},
        )
        self._txid = sent["push_txid"]
        return push["device_info"]["name"], sent.get("step_up_code")

    def finish(self):
        """After the user approved the push, complete the redirects and return Stellic cookies."""
        if self._txid is None:
            raise StellicLoginError("start() was not called")

        deadline = time.monotonic() + self.timeout
        while True:
            status = self._duo(
                "GET",
                "/auth/factors/push/status",
                params={"push_txid": self._txid, "saw_good_news": "false"},
            )["result"]
            if status["result"] == "SUCCESS":
                break
            if status["result"] != "STATUS":
                raise StellicLoginError(f"Duo Push failed: {status}")
            if time.monotonic() > deadline:
                raise StellicLoginError("Duo Push still not approved")
            time.sleep(1)

        # The browser answers "Is this your device?" here; Duo can refuse these
        # (403) and they are not needed to finalize, so failures are ignored.
        for path, body in (
            ("/auth/browser_trust", {"is_trusted": self.trust_browser}),
            ("/auth/remember_me", {}),
        ):
            try:
                self._duo("POST", path, json=body)
            except (StellicLoginError, requests.HTTPError):
                pass
        exit_url = self._duo("GET", "/auth/finalize_auth")["url"]

        # Duo exit -> CAS -> SAML callback page with an auto-submit form to Stellic.
        r = self._get(exit_url)
        form_action = re.search(r'<form[^>]*action="([^"]+)"', r.text)
        form = _form_inputs(r.text)
        if not form_action or "SAMLResponse" not in form:
            raise StellicLoginError(f"No SAML response from CAS (at {r.url})")
        r = self._post(urljoin(r.url, html.unescape(form_action.group(1))), data=form)

        info = self._get(urljoin(STELLIC_URL, "/auth/getsessioninfo/"))
        if '"success": true' not in info.text:
            raise StellicLoginError(
                "Reached Stellic but the session is not authenticated"
            )

        return [
            {
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path,
                "expires": c.expires,
                "secure": c.secure,
            }
            for c in self.session.cookies
            if "stellic" in c.domain
        ]

    def current_courses(self):
        """Fetch the current semester's enrolled courses from the dashboard.

        Reads Stellic's own "Semester Summary" dashboard card, the same XHR the
        web app makes on load, so a non-empty list is real proof the session is
        authenticated and can read the student's data (not just a valid cookie).
        Returns a list of {"code", "title", "units"} dicts.
        """
        r = self._get(
            urljoin(STELLIC_URL, "/dashboard/getwidgetscontent/"),
            params={"widgets": SEMESTER_SUMMARY_WIDGETS},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        widgets = self._stellic_json(r).get("widgets") or []
        content = widgets[0].get("content", {}) if widgets else {}
        courses = content.get("semester_summary", {}).get("courses", [])
        return [
            {"code": c.get("code"), "title": c.get("title"), "units": c.get("units")}
            for c in courses
        ]

    @staticmethod
    def _stellic_json(resp):
        """Parse a Stellic JSON response, stripping its )]}', XSSI guard prefix."""
        return json.loads(re.sub(r"^\)\]\}',\s*", "", resp.text))

    def _get(self, url, **kw):
        r = self.session.get(url, timeout=self.timeout, **kw)
        r.raise_for_status()
        return r

    def _post(self, url, **kw):
        r = self.session.post(url, timeout=self.timeout, **kw)
        r.raise_for_status()
        return r

    def _duo(self, method, path, params=None, json=None):
        """Call the Duo prompt API and return its "response" object."""
        if method == "GET":
            params = {"authkey": self._authkey, **(params or {})}
        else:
            json = {"authkey": self._authkey, **(json or {})}
        r = self.session.request(
            method,
            self._duo_base + path,
            params=params,
            json=json,
            headers=self._duo_headers,
            timeout=self.timeout,
        )
        if not r.ok:
            raise StellicLoginError(f"Duo {path}: HTTP {r.status_code} {r.text[:300]}")
        body = r.json()
        if body.get("stat") != "OK":
            raise StellicLoginError(f"Duo {path}: {body.get('message') or body}")
        return body["response"]

    @staticmethod
    def _cas_error(page_html):
        m = re.search(r'id="loginErrorsPanel"[^>]*>(.*?)</div>', page_html, re.S)
        if not m:
            return None
        return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", m.group(1))).split())


def cookie_header(cookies):
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("netid", nargs="?", help="Princeton netid (prompted if omitted)")
    ap.add_argument(
        "-o",
        "--output",
        default="stellic_cookies.json",
        help="where to write cookies (JSON)",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP / push-approval timeout in seconds",
    )
    args = ap.parse_args()

    netid = args.netid or input("NetID: ").strip()
    password = getpass.getpass("Password: ")

    login = StellicLogin(netid, password, timeout=args.timeout)
    try:
        print("Signing in to CAS...")
        device, code = login.start()
        print(
            f"Duo Push sent to {device}."
            + (f" Verification code: {code}" if code else "")
        )
        input("Approve it on your phone, then press Enter... ")
        cookies = login.finish()
    except (StellicLoginError, requests.RequestException) as e:
        sys.exit(f"Login failed: {e}")

    with open(args.output, "w") as f:
        json.dump(cookies, f, indent=2)
    print(f"Saved {len(cookies)} Stellic cookies to {args.output}")
    print(f"Cookie header:\n{cookie_header(cookies)}")

    # Proof layer: read real data back from Stellic with the fresh session.
    try:
        courses = login.current_courses()
    except (StellicLoginError, requests.RequestException, ValueError, KeyError) as e:
        print(f"\n(Could not read current courses: {e})")
        return
    if courses:
        print(f"\nCurrent semester courses ({len(courses)}):")
        for c in courses:
            units = f"{c['units']:g}" if isinstance(c["units"], (int, float)) else "-"
            print(f"  {c['code'] or '?':<10} {units:>4} u  {c['title'] or ''}")
    else:
        print("\nSession authenticated, but no current-semester courses were found.")


if __name__ == "__main__":
    main()
