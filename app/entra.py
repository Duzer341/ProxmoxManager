"""Microsoft Entra ID sign-in (OpenID Connect authorization code flow with PKCE).

The browser is sent to the tenant's authorize endpoint; Entra redirects back to
/auth/entra/callback with a code, which the server exchanges for an ID token using the
app registration's client secret. The ID token is verified against the tenant's signing
keys (JWKS): signature (RS256), issuer, audience (client ID), tenant, expiry and nonce.

Authorization comes from app roles defined on the app registration: a user must be
assigned the "Admin", "Technician" or "Viewer" role (directly or through a group) to sign
in. With several roles the most powerful one wins (Admin > Technician > Viewer).
"""

import base64
import hashlib
import json
import logging
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlencode

import jwt
import requests

from .loginconfig import GUID_RE, LoginConfig

log = logging.getLogger("app.entra")

HTTP_TIMEOUT = 15
DISCOVERY_TTL = 3600
SCOPES = "openid profile email"
ROLE_MAP = {"admin": "admin", "technician": "technician", "viewer": "viewer"}  # app role value (case-insensitive) -> dashboard role

_cache_lock = threading.Lock()
_discovery: dict[str, tuple[float, dict]] = {}
_jwks: dict[str, tuple[float, dict]] = {}


class EntraError(Exception):
    """Sign-in failed; the message is safe to show to the user."""


def _get_json(url: str) -> dict:
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        raise EntraError(f"Could not reach Microsoft Entra ID ({exc.__class__.__name__}). "
                         "The dashboard server needs outbound HTTPS to login.microsoftonline.com.") from exc
    if r.status_code != 200:
        raise EntraError(f"Microsoft Entra ID returned HTTP {r.status_code} for {url.split('?')[0]}.")
    try:
        return r.json()
    except ValueError as exc:
        raise EntraError("Microsoft Entra ID returned an invalid response.") from exc


def discovery(cfg: LoginConfig, refresh: bool = False) -> dict:
    url = f"{cfg.authority}/{cfg.tenant}/v2.0/.well-known/openid-configuration"
    with _cache_lock:
        hit = _discovery.get(url)
    if hit and not refresh and time.time() - hit[0] < DISCOVERY_TTL:
        return hit[1]
    doc = _get_json(url)
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not doc.get(key):
            raise EntraError(f"The tenant's OpenID configuration has no {key}.")
    with _cache_lock:
        _discovery[url] = (time.time(), doc)
    return doc


def _signing_key(doc: dict, kid: str) -> Any:
    uri = doc["jwks_uri"]
    for attempt in (0, 1):
        with _cache_lock:
            hit = _jwks.get(uri)
        if attempt or not hit or time.time() - hit[0] > DISCOVERY_TTL:
            keys = _get_json(uri)
            with _cache_lock:
                _jwks[uri] = (time.time(), keys)
        else:
            keys = hit[1]
        for k in keys.get("keys", []):
            if k.get("kid") == kid and k.get("kty") == "RSA":
                return jwt.PyJWK(k, algorithm="RS256").key
    raise EntraError("The ID token was signed with an unknown key.")


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def begin(cfg: LoginConfig, stepup: bool = False, acr: str = "", login_hint: str = "") -> tuple[str, dict]:
    """Return (authorize URL, state to keep in the session).

    stepup=True (console re-auth): force a fresh sign-in (prompt=login, max_age=0) and, with
    acr set, ask for that Conditional Access authentication context (claims acrs)."""
    doc = discovery(cfg)
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = _pkce()
    params = {
        "client_id": cfg.client_id,
        "response_type": "code",
        "redirect_uri": cfg.redirect_uri,
        "response_mode": "query",
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    if stepup:
        params["prompt"] = "login"
        params["max_age"] = "0"
        if login_hint:
            params["login_hint"] = login_hint
        if acr:
            params["claims"] = json.dumps({"id_token": {"acrs": {"essential": True, "value": acr}}}, separators=(",", ":"))
    return doc["authorization_endpoint"] + "?" + urlencode(params), {
        "state": state, "nonce": nonce, "verifier": verifier, "ts": int(time.time())}


def finish(cfg: LoginConfig, code: str, pending: dict) -> dict:
    """Exchange the code and return verified claims: oid, tid, username, name, role."""
    doc = discovery(cfg)
    try:
        r = requests.post(doc["token_endpoint"], timeout=HTTP_TIMEOUT, data={
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg.redirect_uri,
            "code_verifier": pending["verifier"],
            "scope": SCOPES,
        })
    except requests.RequestException as exc:
        raise EntraError(f"Could not reach Microsoft Entra ID ({exc.__class__.__name__}).") from exc
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code != 200 or "id_token" not in body:
        desc = (body.get("error_description") or body.get("error") or f"HTTP {r.status_code}").splitlines()[0]
        if "AADSTS7000215" in desc or "AADSTS7000222" in desc:
            desc = "the client secret is wrong or expired. Run manage.py configure-login to enter a new one. (" + desc[:120] + ")"
        raise EntraError("Microsoft Entra ID refused the sign-in: " + desc[:300])
    return verify_id_token(cfg, doc, body["id_token"], pending["nonce"])


def verify_id_token(cfg: LoginConfig, doc: dict, token: str, nonce: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise EntraError("The ID token could not be read.") from exc
    if header.get("alg") != "RS256":
        raise EntraError("The ID token uses an unexpected signing algorithm.")
    key = _signing_key(doc, header.get("kid", ""))
    try:
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=cfg.client_id, issuer=doc["issuer"],
                            leeway=120, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.ExpiredSignatureError as exc:
        raise EntraError("The ID token has expired. Check the dashboard server's clock (NTP).") from exc
    except jwt.InvalidAudienceError as exc:
        raise EntraError("The ID token is for a different application (audience mismatch).") from exc
    except jwt.InvalidIssuerError as exc:
        raise EntraError("The ID token is from a different tenant (issuer mismatch).") from exc
    except jwt.PyJWTError as exc:
        raise EntraError(f"The ID token is not valid ({exc.__class__.__name__}).") from exc
    if not nonce or not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise EntraError("The sign-in response doesn't match this browser session (nonce). Try again.")
    tid = str(claims.get("tid", ""))
    if GUID_RE.match(cfg.tenant) and tid.lower() != cfg.tenant.lower():
        raise EntraError("The account belongs to a different tenant.")
    oid = str(claims.get("oid", ""))
    if not oid:
        raise EntraError("The ID token has no object ID (oid).")
    username = str(claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "").strip().lower()
    if not username:
        raise EntraError("The ID token has no username (preferred_username).")
    from .permissions import highest

    roles = [str(r).lower() for r in (claims.get("roles") or [])]
    role = highest([ROLE_MAP[r] for r in roles if r in ROLE_MAP])
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    acrs = claims.get("acrs") or []
    if isinstance(acrs, str):
        acrs = [acrs]
    return {"oid": oid, "tid": tid, "username": username, "name": str(claims.get("name", ""))[:128],
            "role": role, "roles": claims.get("roles") or [], "iat": _int(claims.get("iat")),
            "auth_time": _int(claims.get("auth_time")), "acrs": [str(a) for a in acrs],
            "amr": [str(a) for a in (claims.get("amr") or [])]}


def clear_cache() -> None:
    with _cache_lock:
        _discovery.clear()
        _jwks.clear()
