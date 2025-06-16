"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import re
import os
import json
import time
from typing import Dict, Any, Tuple, Optional
from urllib.parse import urlparse, urlencode
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.common.security import generate_token
from authlib.jose import jwt
import requests_hardened
import dns.resolver
import requests
from protocol_interfaces import OAuth2ProtocolInterface
from logutils import get_logger

logger = get_logger(__name__)

DEFAULT_CONFIG = {
    "urls": {
        "pds_url": "https://bsky.social",
    },
    "params": {
        "scope": ["atproto", "transition:generic"],
    },
}

HANDLE_REGEX = (
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
DID_REGEX = r"^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$"


def load_credentials(configs: Dict[str, Any]) -> Dict[str, str]:
    """Load OAuth2 credentials from a specified configuration."""

    creds_config = configs.get("credentials", {})
    creds_path = os.path.expanduser(creds_config.get("path", ""))
    if not creds_path:
        raise ValueError("Missing 'credentials.path' in configuration.")
    if not os.path.isabs(creds_path):
        creds_path = os.path.join(os.path.dirname(__file__), creds_path)

    logger.debug("Loading credentials from %s", creds_path)
    with open(creds_path, encoding="utf-8") as f:
        creds = json.load(f)

    return {"client_id": creds["client_id"], "redirect_uri": creds["redirect_uris"][0]}


def is_valid_handle(handle: str) -> bool:
    return re.match(HANDLE_REGEX, handle) is not None


def is_valid_did(did: str) -> bool:
    return re.match(DID_REGEX, did) is not None


def handle_from_doc(doc: dict) -> Optional[str]:
    for aka in doc.get("alsoKnownAs", []):
        if aka.startswith("at://"):
            handle = aka[5:]
            if is_valid_handle(handle):
                return handle
    return None


def pds_endpoint(doc: dict) -> str:
    for svc in doc["service"]:
        if svc["id"] == "#atproto_pds":
            return svc["serviceEndpoint"]
    raise Exception("PDS endpoint not found in DID document")


def resolve_identity(atid: str) -> Tuple[str, str, dict]:
    if is_valid_handle(atid):
        handle = atid
        did = resolve_handle(handle)
        if not did:
            raise Exception("Failed to resolve handle: " + handle)
        doc = resolve_did(did)
        if not doc:
            raise Exception("Failed to resolve DID: " + did)
        doc_handle = handle_from_doc(doc)
        if not doc_handle or doc_handle != handle:
            raise Exception("Handle did not match DID: " + handle)
        return did, handle, doc
    if is_valid_did(atid):
        did = atid
        doc = resolve_did(did)
        if not doc:
            raise Exception("Failed to resolve DID: " + did)
        handle = handle_from_doc(doc)
        if not handle:
            raise Exception("Handle did not match DID: " + handle)
        if resolve_handle(handle) != did:
            raise Exception("Handle did not match DID: " + handle)
        return did, handle, doc


def resolve_handle(handle: str) -> Optional[str]:

    try:
        for record in dns.resolver.resolve(f"_atproto.{handle}", "TXT"):
            val = record.to_text().replace('"', "")
            if val.startswith("did="):
                val = val[4:]
                if is_valid_did(val):
                    return val
    except Exception:
        pass

    try:
        with hardened_http.get_session() as sess:
            resp = sess.get(f"https://{handle}/.well-known/atproto-did")
    except Exception:
        return None

    if resp.status_code != 200:
        return None
    did = resp.text.split()[0]
    if is_valid_did(did):
        return did
    return None


def resolve_did(did: str) -> Optional[dict]:
    if did.startswith("did:plc:"):
        resp = requests.get(f"https://plc.directory/{did}")
        if resp.status_code != 200:
            return None
        return resp.json()

    if did.startswith("did:web:"):
        domain = did[8:]
        assert is_valid_handle(domain)
        try:
            with hardened_http.get_session() as sess:
                resp = sess.get(f"https://{domain}/.well-known/did.json")
        except requests.exceptions.ConnectionError:
            return None
        if resp.status_code != 200:
            return None
        return resp.json()
    raise ValueError("unsupported DID type")


def is_safe_url(url):
    parts = urlparse(url)
    if not (
        parts.scheme == "https"
        and parts.hostname is not None
        and parts.hostname == parts.netloc
        and parts.username is None
        and parts.password is None
        and parts.port is None
    ):
        return False

    segments = parts.hostname.split(".")
    if not (
        len(segments) >= 2
        and segments[-1] not in ["local", "arpa", "internal", "localhost"]
    ):
        return False

    if segments[-1].isdigit():
        return False

    return True


def is_valid_authserver_meta(obj: dict, url: str) -> bool:
    fetch_url = urlparse(url)
    issuer_url = urlparse(obj["issuer"])
    assert issuer_url.hostname == fetch_url.hostname
    assert issuer_url.scheme == "https"
    assert issuer_url.port is None
    assert issuer_url.path in ["", "/"]
    assert issuer_url.params == ""
    assert issuer_url.fragment == ""

    assert "code" in obj["response_types_supported"]
    assert "authorization_code" in obj["grant_types_supported"]
    assert "refresh_token" in obj["grant_types_supported"]
    assert "S256" in obj["code_challenge_methods_supported"]
    assert "none" in obj["token_endpoint_auth_methods_supported"]
    assert "private_key_jwt" in obj["token_endpoint_auth_methods_supported"]
    assert "ES256" in obj["token_endpoint_auth_signing_alg_values_supported"]
    assert "atproto" in obj["scopes_supported"]
    assert obj["authorization_response_iss_parameter_supported"] is True
    assert obj["pushed_authorization_request_endpoint"] is not None
    assert obj["require_pushed_authorization_requests"] is True
    assert "ES256" in obj["dpop_signing_alg_values_supported"]
    if "require_request_uri_registration" in obj:
        assert obj["require_request_uri_registration"] is True
    assert obj["client_id_metadata_document_supported"] is True

    return True


def resolve_pds_authserver(url: str) -> str:
    assert is_safe_url(url)
    with hardened_http.get_session() as sess:
        resp = sess.get(f"{url}/.well-known/oauth-protected-resource")
    resp.raise_for_status()
    assert resp.status_code == 200
    authserver_url = resp.json()["authorization_servers"][0]
    return authserver_url


def fetch_authserver_meta(url: str) -> dict:
    assert is_safe_url(url)
    with hardened_http.get_session() as sess:
        resp = sess.get(f"{url}/.well-known/oauth-authorization-server")
    resp.raise_for_status()

    authserver_meta = resp.json()
    assert is_valid_authserver_meta(authserver_meta, url)
    return authserver_meta


def authserver_dpop_jwt(
    method: str, url: str, nonce: str, dpop_private_jwk: JsonWebKey
) -> str:
    dpop_pub_jwk = json.loads(dpop_private_jwk.as_json(is_private=False))
    body = {
        "jti": generate_token(),
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
        "exp": int(time.time()) + 30,
    }
    if nonce:
        body["nonce"] = nonce
    dpop_proof = jwt.encode(
        {"typ": "dpop+jwt", "alg": "ES256", "jwk": dpop_pub_jwk},
        body,
        dpop_private_jwk,
    ).decode("utf-8")
    return dpop_proof


def send_par_auth_request(
    authserver_meta: dict,
    client_id: str,
    redirect_uri: str,
    scope: str,
    dpop_private_jwk: JsonWebKey,
    state: str = None,
    pkce_verifier: str = None,
    login_hint: str = None,
) -> Dict[str, Any]:
    par_url = authserver_meta["pushed_authorization_request_endpoint"]

    par_body = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    if pkce_verifier:
        code_challenge = create_s256_code_challenge(pkce_verifier)
        code_challenge_method = "S256"
        par_body["code_challenge"] = code_challenge
        par_body["code_challenge_method"] = code_challenge_method

    if state:
        par_body["state"] = state

    if login_hint:
        par_body["login_hint"] = login_hint

    dpop_authserver_nonce = ""
    dpop_proof = authserver_dpop_jwt(
        "POST", par_url, dpop_authserver_nonce, dpop_private_jwk
    )

    assert is_safe_url(par_url)
    with hardened_http.get_session() as sess:
        resp = sess.post(
            par_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "DPoP": dpop_proof,
            },
            data=par_body,
        )

    if resp.status_code == 400 and resp.json()["error"] == "use_dpop_nonce":
        dpop_authserver_nonce = resp.headers["DPoP-Nonce"]
        logger.warning(
            "DPoP nonce required by auth server, retrying with new nonce: %s.",
            dpop_authserver_nonce,
        )
        dpop_proof = authserver_dpop_jwt(
            "POST", par_url, dpop_authserver_nonce, dpop_private_jwk
        )
        with hardened_http.get_session() as sess:
            resp = sess.post(
                par_url,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "DPoP": dpop_proof,
                },
                data=par_body,
            )

    return {
        "pkce_verifier": pkce_verifier,
        "state": state,
        "dpop_authserver_nonce": dpop_authserver_nonce,
        "response": resp,
    }


def initial_token_request(
    client_id: str,
    redirect_uri: str,
    authserver_iss: str,
    pkce_verifier: str,
    dpop_private_jwk: JsonWebKey,
    dpop_authserver_nonce: str,
    code: str,
) -> Tuple[dict, str]:
    authserver_meta = fetch_authserver_meta(authserver_iss)

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": pkce_verifier,
    }

    token_url = authserver_meta["token_endpoint"]
    dpop_private_jwk = JsonWebKey.import_key(json.loads(dpop_private_jwk))
    dpop_proof = authserver_dpop_jwt(
        "POST", token_url, dpop_authserver_nonce, dpop_private_jwk
    )

    assert is_safe_url(token_url)
    with hardened_http.get_session() as sess:
        resp = sess.post(token_url, data=params, headers={"DPoP": dpop_proof})

    if resp.status_code == 400 and resp.json()["error"] == "use_dpop_nonce":
        dpop_authserver_nonce = resp.headers["DPoP-Nonce"]
        logger.warning(
            "DPoP nonce required by auth server, retrying with new nonce: %s.",
            dpop_authserver_nonce,
        )
        dpop_proof = authserver_dpop_jwt(
            "POST", token_url, dpop_authserver_nonce, dpop_private_jwk
        )
        with hardened_http.get_session() as sess:
            resp = sess.post(token_url, data=params, headers={"DPoP": dpop_proof})

    resp.raise_for_status()
    token_body = resp.json()

    return token_body, dpop_authserver_nonce


hardened_http = requests_hardened.Manager(
    requests_hardened.Config(
        default_timeout=(2, 10),
        never_redirect=True,
        ip_filter_enable=True,
        ip_filter_allow_loopback_ips=False,
        user_agent_override="BlueskyOAuth2Adapter",
    )
)


class BlueskyOAuth2Adapter(OAuth2ProtocolInterface):
    """Adapter for integrating Bluesky's OAuth2 protocol."""

    def __init__(self):
        self.default_config = DEFAULT_CONFIG
        self.credentials = load_credentials(self.config)

    def get_authorization_url(self, **kwargs) -> Dict[str, Any]:
        code_verifier = kwargs.get("code_verifier")
        autogenerate_code_verifier = kwargs.pop("autogenerate_code_verifier", False)
        redirect_url = kwargs.pop("redirect_url", None)
        client_id = self.credentials["client_id"]

        authserver_url = self.default_config["urls"]["pds_url"]

        if not is_safe_url(authserver_url):
            logger.error("Insecure auth server URL: %s", authserver_url)
            raise ValueError("Insecure auth server URL, please check the PDS URL.")

        try:
            authserver_meta = fetch_authserver_meta(authserver_url)
        except Exception as err:
            logger.error("Failed to fetch auth server metadata: %s", err)
            raise

        dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

        if autogenerate_code_verifier and not code_verifier:
            code_verifier = generate_token(48)

        try:
            par_result = send_par_auth_request(
                client_id=client_id,
                authserver_meta=authserver_meta,
                redirect_uri=redirect_url or self.credentials["redirect_uri"],
                pkce_verifier=code_verifier,
                scope=" ".join(self.default_config["params"]["scope"]),
                dpop_private_jwk=dpop_private_jwk,
                state=kwargs.get("state"),
            )
            if par_result["response"].status_code == 400:
                logger.error(
                    "PAR request failed with HTTP 400: %s",
                    par_result["response"].json(),
                )
            par_result["response"].raise_for_status()
        except Exception as err:
            logger.error("Failed to send PAR auth request: %s", err)
            raise

        par_request_uri = par_result["response"].json()["request_uri"]
        auth_url = authserver_meta["authorization_endpoint"]
        if not is_safe_url(auth_url):
            logger.error("Insecure auth URL: %s", auth_url)
            raise ValueError("Insecure auth URL, please check the PDS URL.")

        qparam = urlencode({"client_id": client_id, "request_uri": par_request_uri})
        authorization_url = f"{auth_url}?{qparam}"

        logger.debug("Authorization URL generated: %s", authorization_url)

        return {
            "authorization_url": authorization_url,
            "state": par_result.get("state"),
            "code_verifier": par_result.get("pkce_verifier"),
            "client_id": client_id,
            "scope": ",".join(self.default_config["params"]["scope"]),
            "redirect_uri": redirect_url or self.credentials["redirect_uri"],
            "dpop_private_jwk": dpop_private_jwk.as_json(is_private=True),
            "authserver_iss": authserver_url,
            "dpop_authserver_nonce": par_result.get("dpop_authserver_nonce"),
        }

    def exchange_code_and_fetch_user_info(self, code, **kwargs):
        redirect_url = kwargs.pop("redirect_url", None)
        code_verifier = kwargs.pop("code_verifier", None)
        authserver_iss = kwargs.pop("authserver_iss", None)
        dpop_private_jwk = kwargs.pop("dpop_private_jwk", None)
        dpop_authserver_nonce = kwargs.pop("dpop_authserver_nonce", None)

        if not code_verifier:
            raise ValueError("PKCE code verifier is required for token exchange.")

        if not dpop_private_jwk:
            raise ValueError("DPoP private JWK is required for token exchange.")

        if not dpop_authserver_nonce:
            raise ValueError("DPoP auth server nonce is required for token exchange.")

        client_id = self.credentials["client_id"]

        tokens, dpop_authserver_nonce = initial_token_request(
            client_id=client_id,
            redirect_uri=redirect_url or self.credentials["redirect_uri"],
            code=code,
            pkce_verifier=code_verifier,
            dpop_authserver_nonce=dpop_authserver_nonce,
            dpop_private_jwk=dpop_private_jwk,
            authserver_iss=authserver_iss or self.default_config["urls"]["pds_url"],
        )

        did = tokens["sub"]
        if not is_valid_did(did):
            raise ValueError("Invalid DID format.")

        did, handle, did_doc = resolve_identity(did)
        pds_url = pds_endpoint(did_doc)
        authserver_url = resolve_pds_authserver(pds_url)

        if authserver_url != authserver_iss:
            raise ValueError("Authorization Server mismatch.")

        if self.default_config["params"]["scope"] != tokens["scope"]:
            raise ValueError("Scope mismatch.")

        userinfo = {}

        return {"token": tokens, "userinfo": userinfo}

    def revoke_token(self, token, **kwargs):
        return super().revoke_token(token, **kwargs)

    def send_message(self, token, message, **kwargs):
        return super().send_message(token, message, **kwargs)
