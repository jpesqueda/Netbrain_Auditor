"""NetBrain REST client, based on the Lookup 2.6.4 RC4 session design."""
import json
import logging
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

LOG = logging.getLogger("netbrain_auditor")
BASE = "/ServicesAPI/API/V1"
SESSION = BASE + "/Session"
DEVICES = BASE + "/CMDB/Devices"
DOMAIN = SESSION + "/CurrentDomain"


class AuditError(Exception):
    """An expected audit failure."""


class AuthenticationError(AuditError):
    pass


class ConnectivityError(AuditError):
    pass


class APIError(AuditError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def ci_get(obj, key, default=None):
    return next((v for k, v in obj.items() if k.casefold() == key.casefold()), default)


def require_list(obj, key):
    value = ci_get(obj, key)
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise APIError(f"Invalid or missing {key} array")
    return value


class NetBrain:
    def __init__(self, url, user, password, *, auth_id=None, insecure=False,
                 ca_file=None, timeout=30, retries=3, backoff=1.0):
        p = urlsplit(url)
        if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment:
            raise AuditError("Use an HTTPS NetBrain base URL without credentials or query parameters.")
        self.url = url.rstrip("/")
        self.user = user
        self._password = password
        self.auth_id = auth_id
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.token = None
        self.renewed = False
        self.domain = None
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context(cafile=ca_file)
        self.opener = build_opener(HTTPSHandler(context=ctx), NoRedirect())
        if insecure:
            LOG.warning("TLS certificate verification disabled")

    def _request(self, method, path, params=None, body=None, auth=True, probe=False):
        url = self.url + path
        if params:
            url += "?" + urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(self.retries + 1):
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if auth and self.token:
                headers["Token"] = self.token
            req = Request(url, data=data, headers=headers, method=method)
            retry_after = None
            try:
                with self.opener.open(req, timeout=self.timeout) as res:
                    status = res.status
                    payload = res.read()
            except HTTPError as exc:
                status = exc.code
                retry_after = exc.headers.get("Retry-After")
                exc.close()
                payload = b""
            except (URLError, TimeoutError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, ssl.SSLError):
                    raise ConnectivityError("TLS verification or handshake failed") from None
                if isinstance(reason, TimeoutError) and attempt < self.retries:
                    self._delay(attempt, None, path, "timeout")
                    continue
                raise ConnectivityError(f"Network request failed at {path}: {type(reason).__name__}") from None
            LOG.debug("%s %s HTTP %s", method, path, status)
            if status == 429 or 500 <= status < 600:
                if attempt < self.retries:
                    self._delay(attempt, retry_after, path, status)
                    continue
            if probe:
                return status
            if auth and status == 401:
                if self.renewed:
                    raise AuthenticationError("Session rejected after one renewal")
                self.renewed = True
                LOG.warning("Session rejected; renewing once")
                self.login()
                if self.domain:
                    self._request("PUT", DOMAIN, body=self.domain)
                # Reissue once with a fresh retry budget; renewed guards recursion.
                return self._request(method, path, params=params, body=body, auth=auth)
            if not auth and status in (400, 401, 403):
                raise AuthenticationError(f"Authentication rejected (HTTP {status})")
            if not 200 <= status < 300:
                raise APIError(f"{method} {path} failed: HTTP {status}")
            if method == "DELETE" and not payload:
                return {}
            try:
                obj = json.loads(payload)
            except (ValueError, UnicodeError):
                raise APIError(f"Invalid JSON from {path}") from None
            if not isinstance(obj, dict):
                raise APIError(f"Invalid response object from {path}")
            code = ci_get(obj, "statusCode")
            if str(code) not in ("790200", "200", "0"):
                error_type = AuthenticationError if not auth else APIError
                raise error_type(f"{path}: unexpected NetBrain statusCode {code!r}")
            return obj
        raise APIError("Retry budget exhausted")

    def _delay(self, attempt, retry_after, path, reason):
        delay = min(30.0, self.backoff * 2 ** min(attempt, 20))
        if retry_after:
            try:
                delay = max(0.0, min(float(retry_after), 120.0))
            except ValueError:
                pass
        LOG.warning("Retry %d/%d: %s (%s), wait %.1fs", attempt + 1, self.retries, path, reason, delay)
        time.sleep(delay)

    def validate_connection(self):
        status = self._request("GET", SESSION, auth=False, probe=True)
        if status >= 500 or status == 429 or 300 <= status < 400:
            raise ConnectivityError(f"Connectivity probe returned HTTP {status}")
        LOG.info("Connectivity probe HTTP %s", status)

    def login(self):
        body = {"username": self.user, "password": self._password}
        if self.auth_id:
            body["authentication_id"] = self.auth_id
        try:
            obj = self._request("POST", SESSION, body=body, auth=False)
        finally:
            body.clear()
        token = ci_get(obj, "token")
        if not isinstance(token, str) or not token:
            raise AuthenticationError("Authentication response had no token")
        self.token = token
        LOG.info("Authentication successful")

    def select_domain(self, tenant, domain, choose):
        tenants = require_list(self._request("GET", BASE + "/CMDB/Tenants"), "tenants")
        t = choose(tenants, tenant, "tenantName", "tenantId", "tenant")
        tid = ci_get(t, "tenantId")
        domains = require_list(self._request("GET", BASE + "/CMDB/Domains", {"tenantId": tid}), "domains")
        d = choose(domains, domain, "domainName", "domainId", "domain")
        payload = {"tenantId": tid, "domainId": ci_get(d, "domainId")}
        if not all(payload.values()):
            raise APIError("Tenant or domain ID missing")
        self._request("PUT", DOMAIN, body=payload)
        self.domain = payload
        return f"{ci_get(t, 'tenantName')} / {ci_get(d, 'domainName')}"

    def device_page(self, skip, limit):
        return self._request("GET", DEVICES, {"fullattr": 1, "version": 1, "skip": skip, "limit": limit})

    def close(self):
        try:
            if self.token:
                # Do not renew a token during logout.
                self.renewed = True
                self._request("DELETE", SESSION)
        except AuditError as exc:
            LOG.warning("Session cleanup: %s", exc)
        finally:
            self.token = None
            self._password = None
