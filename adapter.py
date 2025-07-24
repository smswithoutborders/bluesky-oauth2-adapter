"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import re
import os
import json
import time
import sqlite3
import math
import textwrap
from datetime import datetime, timezone
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

DEFAULT_SESSIONS_DIR = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "sessions"
)

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

BLUESKY_CHARACTER_LIMIT = 300


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


def pds_dpop_jwt(
    method: str,
    url: str,
    access_token: str,
    nonce: str,
    dpop_private_jwk: JsonWebKey,
) -> str:
    dpop_pub_jwk = json.loads(dpop_private_jwk.as_json(is_private=False))
    body = {
        "iat": int(time.time()),
        "exp": int(time.time()) + 10,
        "jti": generate_token(),
        "htm": method,
        "htu": url,
        "ath": create_s256_code_challenge(access_token),
    }
    if nonce:
        body["nonce"] = nonce
    dpop_proof = jwt.encode(
        {"typ": "dpop+jwt", "alg": "ES256", "jwk": dpop_pub_jwk},
        body,
        dpop_private_jwk,
    ).decode("utf-8")
    return dpop_proof


def pds_authed_req(method: str, url: str, token: dict, body=None) -> Any:
    dpop_private_jwk = JsonWebKey.import_key(json.loads(token["dpop_private_jwk"]))
    dpop_pds_nonce = token.get("dpop_pds_nonce")
    access_token = token["access_token"]

    for i in range(2):
        dpop_jwt = pds_dpop_jwt(
            method,
            url,
            access_token,
            dpop_pds_nonce,
            dpop_private_jwk,
        )

        with hardened_http.get_session() as sess:
            resp = sess.post(
                url,
                headers={
                    "Authorization": f"DPoP {access_token}",
                    "DPoP": dpop_jwt,
                },
                json=body,
            )

        if resp.status_code in [400, 401] and resp.json()["error"] == "use_dpop_nonce":
            dpop_pds_nonce = resp.headers["DPoP-Nonce"]
            logger.warning("Retrying with new PDS DPoP nonce: %s", dpop_pds_nonce)
            # TODO: return the new nonce to the caller
            continue
        break

    return resp


def refresh_token_request(token: dict, client_id: str) -> Tuple[dict, str]:
    authserver_url = token["authserver_iss"]
    authserver_meta = fetch_authserver_meta(authserver_url)

    params = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": token["refresh_token"],
    }

    token_url = authserver_meta["token_endpoint"]
    dpop_private_jwk = JsonWebKey.import_key(json.loads(token["dpop_private_jwk"]))
    dpop_authserver_nonce = token["dpop_authserver_nonce"]
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

    if resp.status_code not in [200, 201]:
        logger.error("Token Refresh Error: %s", resp.json())

    resp.raise_for_status()
    token_body = resp.json()
    token_body["dpop_authserver_nonce"] = dpop_authserver_nonce

    return token_body, dpop_authserver_nonce


def db_query(
    db_path: str,
    query: str,
    params: Optional[Tuple[Any, ...]] = None,
    first: bool = False,
) -> Any:
    if not os.path.exists(db_path):
        initialize_database(db_path)

    logger.debug("Executing query on database: %s", db_path)
    logger.debug("Query: %s", query)
    if params:
        logger.debug("Parameters: %s", params)

    conn = None
    cursor = None

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        conn.commit()
        result = cursor.fetchall()
        logger.info("Query executed successfully. Rows fetched: %d", len(result))

        if cursor.description is None:
            return None

        if first:
            if result:
                logger.debug("Returning first row as dictionary.")
                return {
                    desc[0]: result[0][idx]
                    for idx, desc in enumerate(cursor.description)
                }
            else:
                return None

        logger.debug("Returning full result set as list of dictionaries.")
        return [
            {desc[0]: row[idx] for idx, desc in enumerate(cursor.description)}
            for row in result
        ]

    except sqlite3.Error as e:
        logger.error("Database error: %s", e)
        raise
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()
        logger.debug("Database connection closed.")


def initialize_database(db_path: str) -> None:
    schema_path = os.path.expanduser("schema.sql")
    schema_path = os.path.join(os.path.dirname(__file__), schema_path)

    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    logger.debug("Initializing database at %s using schema %s", db_path, schema_path)
    try:
        with open(schema_path, "r", encoding="utf-8") as schema_file:
            schema_sql = schema_file.read()

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.executescript(schema_sql)
        conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.error("Database initialization error: %s", e)
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


hardened_http = requests_hardened.Manager(
    requests_hardened.Config(
        default_timeout=(2, 10),
        never_redirect=True,
        ip_filter_enable=True,
        ip_filter_allow_loopback_ips=False,
        user_agent_override="BlueskyOAuth2Adapter",
    )
)


def split_message_into_chunks(
    message: str, max_length: int = BLUESKY_CHARACTER_LIMIT
) -> list:
    """Split a message into chunks that fit within Bluesky's character limit."""
    message_length = len(message)
    if message_length <= max_length:
        return [message]

    # Account for thread indicator like " (1/3)" - reserve 10 chars
    effective_max_length = max_length - 10

    threads_required = math.ceil(message_length / effective_max_length)
    chars_per_thread = math.ceil(message_length / threads_required)

    return textwrap.wrap(message, chars_per_thread, break_long_words=False)


def create_post_payload(did: str, text: str, created_at: str, reply_to=None) -> dict:
    """Create a Bluesky post payload."""
    payload = {
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": created_at,
        },
    }

    if reply_to is not None:
        payload["record"]["reply"] = reply_to

    return payload


class BlueskyOAuth2Adapter(OAuth2ProtocolInterface):
    """Adapter for integrating Bluesky's OAuth2 protocol."""

    def __init__(self):
        self.default_config = DEFAULT_CONFIG
        self.credentials = load_credentials(self.config)

    def get_authorization_url(self, **kwargs) -> Dict[str, Any]:
        code_verifier = kwargs.get("code_verifier")
        autogenerate_code_verifier = kwargs.pop("autogenerate_code_verifier", False)
        redirect_url = kwargs.pop("redirect_url", None)
        request_identifier = kwargs.pop("request_identifier", None)
        base_path = kwargs.pop("base_path", "") or DEFAULT_SESSIONS_DIR
        db_path = os.path.join(base_path, "oauth_session.db")
        client_id = self.credentials["client_id"]

        os.makedirs(base_path, exist_ok=True)

        if not request_identifier:
            logger.error("Missing request identifier.")
            raise ValueError("Missing request identifier for authorization URL.")

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
        query = "INSERT OR REPLACE INTO oauth_sessions (request_identifier, dpop_private_jwk, authserver_iss, dpop_authserver_nonce) VALUES (?, ?, ?, ?)"
        db_query(
            db_path,
            query,
            (
                request_identifier,
                dpop_private_jwk.as_json(is_private=True),
                authserver_url,
                par_result.get("dpop_authserver_nonce"),
            ),
        )

        return {
            "authorization_url": authorization_url,
            "state": par_result.get("state"),
            "code_verifier": par_result.get("pkce_verifier"),
            "client_id": client_id,
            "scope": ",".join(self.default_config["params"]["scope"]),
            "redirect_uri": redirect_url or self.credentials["redirect_uri"],
        }

    def exchange_code_and_fetch_user_info(self, code, **kwargs):
        redirect_url = kwargs.pop("redirect_url", None)
        code_verifier = kwargs.pop("code_verifier", None)
        request_identifier = kwargs.pop("request_identifier", None)
        base_path = kwargs.pop("base_path", "") or DEFAULT_SESSIONS_DIR
        db_path = os.path.join(base_path, "oauth_session.db")

        os.makedirs(base_path, exist_ok=True)

        if not request_identifier:
            logger.error("Missing request identifier.")
            raise ValueError("Missing request identifier for authorization URL.")

        if not code_verifier:
            raise ValueError("PKCE code verifier is required for token exchange.")

        query = "SELECT dpop_private_jwk, authserver_iss, dpop_authserver_nonce FROM oauth_sessions WHERE request_identifier = ?"
        result = db_query(db_path, query, (request_identifier,), first=True)

        if not result:
            logger.error(
                "No session found for request identifier: %s", request_identifier
            )
            raise ValueError("No session found for the provided request identifier.")

        dpop_private_jwk = result["dpop_private_jwk"]
        authserver_iss = result["authserver_iss"]
        dpop_authserver_nonce = result["dpop_authserver_nonce"]
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

        if " ".join(self.default_config["params"]["scope"]) != tokens["scope"]:
            raise ValueError("Scope mismatch.")

        tokens["pds_url"] = pds_url
        tokens["authserver_iss"] = authserver_url
        tokens["dpop_authserver_nonce"] = dpop_authserver_nonce
        tokens["dpop_private_jwk"] = dpop_private_jwk

        userinfo = {"account_identifier": handle}

        query = "DELETE FROM oauth_sessions WHERE request_identifier = ?"
        db_query(db_path, query, (request_identifier,))
        logger.debug("Deleted session for request identifier: %s", request_identifier)
        return {"token": tokens, "userinfo": userinfo}

    def revoke_token(self, token, **kwargs):
        return True

    def send_message(self, token, message, **kwargs):
        pds_url = token["pds_url"]
        did = token["sub"]
        req_url = f"{pds_url}/xrpc/com.atproto.repo.createRecord"
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        message_chunks = split_message_into_chunks(message)

        refreshed_token = token
        try:
            refreshed_token, dpop_authserver_nonce = refresh_token_request(
                token=token, client_id=self.credentials["client_id"]
            )
            refreshed_token["dpop_authserver_nonce"] = dpop_authserver_nonce
            refreshed_token["dpop_private_jwk"] = token["dpop_private_jwk"]
            refreshed_token["pds_url"] = pds_url
            refreshed_token["authserver_iss"] = token["authserver_iss"]

            thread_posts = []
            parent_post = None
            root_post = None

            for i, chunk in enumerate(message_chunks):
                if len(message_chunks) > 1:
                    thread_text = f"{chunk} ({i+1}/{len(message_chunks)})"
                else:
                    thread_text = chunk

                reply_to = None
                if parent_post:
                    reply_to = {"root": root_post, "parent": parent_post}

                body = create_post_payload(did, thread_text, now, reply_to)

                resp = pds_authed_req("POST", req_url, token=refreshed_token, body=body)
                if resp.status_code not in [200, 201]:
                    logger.error("PDS HTTP Error: %s", resp.json())
                resp.raise_for_status()

                post_data = resp.json()
                post_reference = {"uri": post_data["uri"], "cid": post_data["cid"]}

                thread_posts.append(post_reference)

                if i == 0:
                    root_post = post_reference
                parent_post = post_reference

                now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            logger.info("Successfully sent message with %d posts.", len(thread_posts))
            return {"success": True, "refreshed_token": refreshed_token}
        except requests.exceptions.HTTPError as e:
            logger.error("Failed to send message: %s", e)
            return {
                "success": False,
                "message": e.response.text,
                "refreshed_token": refreshed_token,
            }
