"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import os
import json
import time
from typing import Dict, Any, Tuple
from urllib.parse import urlparse, urlencode
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.common.security import generate_token
from authlib.jose import jwt
import requests_hardened
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
) -> Tuple[str, str, str, Any]:
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

    return pkce_verifier, state, dpop_authserver_nonce, resp


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
            pkce_verifier, state, _, resp = send_par_auth_request(
                client_id=client_id,
                authserver_meta=authserver_meta,
                redirect_uri=redirect_url or self.credentials["redirect_uri"],
                pkce_verifier=code_verifier,
                scope=" ".join(self.default_config["params"]["scope"]),
                dpop_private_jwk=dpop_private_jwk,
                state=kwargs.get("state"),
            )
            if resp.status_code == 400:
                logger.error("PAR request failed with HTTP 400: %s", resp.json())
            resp.raise_for_status()
        except Exception as err:
            logger.error("Failed to send PAR auth request: %s", err)
            raise

        par_request_uri = resp.json()["request_uri"]
        auth_url = authserver_meta["authorization_endpoint"]
        if not is_safe_url(auth_url):
            logger.error("Insecure auth URL: %s", auth_url)
            raise ValueError("Insecure auth URL, please check the PDS URL.")

        qparam = urlencode({"client_id": client_id, "request_uri": par_request_uri})
        authorization_url = f"{auth_url}?{qparam}"

        logger.debug("Authorization URL generated: %s", authorization_url)

        return {
            "authorization_url": authorization_url,
            "state": state,
            "code_verifier": pkce_verifier,
            "client_id": client_id,
            "scope": ",".join(self.default_config["params"]["scope"]),
            "redirect_uri": redirect_url or self.credentials["redirect_uri"],
        }

    def exchange_code_and_fetch_user_info(self, code, **kwargs):
        return super().exchange_code_and_fetch_user_info(code, **kwargs)

    def revoke_token(self, token, **kwargs):
        return super().revoke_token(token, **kwargs)

    def send_message(self, token, message, **kwargs):
        return super().send_message(token, message, **kwargs)
