# SPDX-License-Identifier: GPL-3.0-only

import json
import math
import re
import textwrap
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import dns.resolver
import requests
import requests_hardened
from authlib.common.security import generate_token
from authlib.jose import JsonWebKey, jwt
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from config import Credentials
from logutils import get_logger

logger = get_logger(__name__)

HANDLE_REGEX = (
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
DID_REGEX = r"^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$"
MAX_EMBED_IMAGES = 4
MAX_IMAGE_BYTES = 1000000
SUPPORTED_IMAGE_MIMETYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}


class ATProtoError(Exception):
    """Base class for all AT Protocol client errors."""


class InvalidIdentifierError(ATProtoError):
    """Raised when an AT identifier is neither a valid handle nor a valid DID."""


class IdentityResolutionError(ATProtoError):
    """Raised when a handle/DID fails to resolve, or resolution is inconsistent."""


class AuthServerError(ATProtoError):
    """Raised when the PDS/auth server returns an unexpected or unsafe response."""


class AttachmentError(ATProtoError):
    """Raised when an attachment cannot be uploaded or embedded in a post."""


def is_valid_handle(handle: str) -> bool:
    return re.match(HANDLE_REGEX, handle) is not None


def is_valid_did(did: str) -> bool:
    return re.match(DID_REGEX, did) is not None


def is_safe_url(url: str) -> bool:
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

    return not segments[-1].isdigit()


def handle_from_doc(doc: dict) -> Optional[str]:
    for aka in doc.get("alsoKnownAs", []):
        if aka.startswith("at://"):
            handle = aka[5:]
            if is_valid_handle(handle):
                return handle
    return None


def pds_endpoint(doc: dict) -> str:
    for svc in doc.get("service", []):
        if svc.get("id") == "#atproto_pds":
            return svc["serviceEndpoint"]
    raise AuthServerError("PDS endpoint not found in DID document.")


@dataclass
class Attachment:
    data: bytes
    filename: str
    mimetype: str


def create_post_payload(
    did: str,
    text: str,
    created_at: str,
    reply_to: Optional[dict] = None,
    embed: Optional[dict] = None,
) -> dict:
    """Create a Bluesky post record payload."""
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
    if embed is not None:
        payload["record"]["embed"] = embed
    return payload


class ATProtoClient:
    def __init__(self, credentials: Credentials):
        self.credentials = credentials
        self.http = requests_hardened.Manager(
            requests_hardened.Config(
                default_timeout=(2, 10),
                never_redirect=True,
                ip_filter_enable=True,
                ip_filter_allow_loopback_ips=False,
                user_agent_override="BlueskyOAuth2Adapter",
            )
        )

    def resolve_handle(self, handle: str) -> Optional[str]:
        try:
            for record in dns.resolver.resolve(f"_atproto.{handle}", "TXT"):
                val = record.to_text().replace('"', "")
                if val.startswith("did="):
                    val = val[4:]
                    if is_valid_did(val):
                        return val
        except Exception:
            logger.debug("DNS TXT lookup for handle %s had no usable record.", handle)

        try:
            with self.http.get_session() as sess:
                resp = sess.get(f"https://{handle}/.well-known/atproto-did")
        except Exception:
            logger.exception("Failed to fetch atproto-did for handle: %s", handle)
            return None

        if resp.status_code != 200:
            return None

        did = resp.text.split()[0]
        return did if is_valid_did(did) else None

    def resolve_did(self, did: str) -> Optional[dict]:
        if did.startswith("did:plc:"):
            resp = requests.get(f"https://plc.directory/{did}")
            if resp.status_code != 200:
                return None
            return resp.json()

        if did.startswith("did:web:"):
            domain = did[8:]
            if not is_valid_handle(domain):
                raise InvalidIdentifierError(f"Invalid did:web domain: {domain}")
            try:
                with self.http.get_session() as sess:
                    resp = sess.get(f"https://{domain}/.well-known/did.json")
            except requests.exceptions.ConnectionError:
                logger.exception("Failed to connect while resolving did:web: %s", did)
                return None
            if resp.status_code != 200:
                return None
            return resp.json()

        raise InvalidIdentifierError(f"Unsupported DID method: {did}")

    def resolve_identity(self, atid: str) -> Tuple[str, str, dict]:
        if is_valid_handle(atid):
            handle = atid
            did = self.resolve_handle(handle)
            if not did:
                raise IdentityResolutionError(f"Failed to resolve handle: {handle}")

            doc = self.resolve_did(did)
            if not doc:
                raise IdentityResolutionError(f"Failed to resolve DID: {did}")

            doc_handle = handle_from_doc(doc)
            if not doc_handle or doc_handle != handle:
                raise IdentityResolutionError(f"Handle did not match DID: {handle}")

            return did, handle, doc

        if is_valid_did(atid):
            did = atid
            doc = self.resolve_did(did)
            if not doc:
                raise IdentityResolutionError(f"Failed to resolve DID: {did}")

            handle = handle_from_doc(doc)
            if not handle:
                raise IdentityResolutionError(
                    f"No valid handle found in DID document for: {did}"
                )
            if self.resolve_handle(handle) != did:
                raise IdentityResolutionError(f"Handle did not match DID: {handle}")

            return did, handle, doc

        raise InvalidIdentifierError(f"'{atid}' is not a valid handle or DID.")

    def resolve_account(self, atid: str) -> Dict[str, str]:
        did, handle, doc = self.resolve_identity(atid)
        pds_url = pds_endpoint(doc)
        authserver_url = self.resolve_pds_authserver(pds_url)
        return {
            "did": did,
            "handle": handle,
            "pds_url": pds_url,
            "authserver_iss": authserver_url,
        }

    @staticmethod
    def _validate_authserver_meta(obj: dict, url: str) -> bool:
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

    def resolve_pds_authserver(self, pds_url: str) -> str:
        if not is_safe_url(pds_url):
            raise AuthServerError(f"Unsafe PDS URL: {pds_url}")
        with self.http.get_session() as sess:
            resp = sess.get(f"{pds_url}/.well-known/oauth-protected-resource")
        resp.raise_for_status()
        return resp.json()["authorization_servers"][0]

    def fetch_authserver_meta(self, authserver_url: Optional[str] = None) -> dict:
        url = authserver_url or self.credentials.PDS_URL
        if not is_safe_url(url):
            raise AuthServerError(f"Unsafe auth server URL: {url}")

        with self.http.get_session() as sess:
            resp = sess.get(f"{url}/.well-known/oauth-authorization-server")
        resp.raise_for_status()

        meta = resp.json()
        try:
            self._validate_authserver_meta(meta, url)
        except (AssertionError, KeyError) as exc:
            raise AuthServerError(
                f"Auth server metadata failed validation: {url}"
            ) from exc
        return meta

    def _authserver_dpop_jwt(
        self, method: str, url: str, nonce: str, key: JsonWebKey
    ) -> str:
        pub_jwk = json.loads(key.as_json(is_private=False))
        body = {
            "jti": generate_token(),
            "htm": method,
            "htu": url,
            "iat": int(time.time()),
            "exp": int(time.time()) + self.credentials.AUTHSERVER_DPOP_TTL,
        }
        if nonce:
            body["nonce"] = nonce
        return jwt.encode(
            {"typ": "dpop+jwt", "alg": "ES256", "jwk": pub_jwk}, body, key
        ).decode("utf-8")

    def _pds_dpop_jwt(
        self, method: str, url: str, access_token: str, nonce: str, key: JsonWebKey
    ) -> str:
        pub_jwk = json.loads(key.as_json(is_private=False))
        body = {
            "iat": int(time.time()),
            "exp": int(time.time()) + self.credentials.PDS_DPOP_TTL,
            "jti": generate_token(),
            "htm": method,
            "htu": url,
            "ath": create_s256_code_challenge(access_token),
        }
        if nonce:
            body["nonce"] = nonce
        return jwt.encode(
            {"typ": "dpop+jwt", "alg": "ES256", "jwk": pub_jwk}, body, key
        ).decode("utf-8")

    def _post_with_dpop_retry(
        self, url: str, data: dict, key: JsonWebKey, nonce: str
    ) -> Tuple[Any, str]:
        """POST a DPoP-protected auth-server request, retrying once on a fresh nonce challenge."""
        if not is_safe_url(url):
            raise AuthServerError(f"Unsafe auth server endpoint: {url}")

        def _do_post(dpop_nonce: str):
            proof = self._authserver_dpop_jwt("POST", url, dpop_nonce, key)
            with self.http.get_session() as sess:
                return sess.post(
                    url,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "DPoP": proof,
                    },
                    data=data,
                )

        resp = _do_post(nonce)
        if resp.status_code == 400 and resp.json().get("error") == "use_dpop_nonce":
            nonce = resp.headers["DPoP-Nonce"]
            logger.warning(
                "DPoP nonce required by auth server, retrying with new nonce."
            )
            resp = _do_post(nonce)

        return resp, nonce

    def request_par(
        self,
        authserver_meta: dict,
        client_id: str,
        redirect_uri: str,
        scope: str,
        dpop_private_jwk: JsonWebKey,
        state: Optional[str] = None,
        pkce_verifier: Optional[str] = None,
        login_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        par_url = authserver_meta["pushed_authorization_request_endpoint"]

        par_body = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }
        if pkce_verifier:
            par_body["code_challenge"] = create_s256_code_challenge(pkce_verifier)
            par_body["code_challenge_method"] = "S256"
        if state:
            par_body["state"] = state
        if login_hint:
            par_body["login_hint"] = login_hint

        resp, dpop_authserver_nonce = self._post_with_dpop_retry(
            par_url, par_body, dpop_private_jwk, nonce=""
        )
        if resp.status_code == 400:
            logger.error("PAR request rejected with HTTP 400.")
        resp.raise_for_status()

        return {
            "request_uri": resp.json()["request_uri"],
            "pkce_verifier": pkce_verifier,
            "state": state,
            "dpop_authserver_nonce": dpop_authserver_nonce,
        }

    def exchange_code(
        self,
        client_id: str,
        redirect_uri: str,
        code: str,
        pkce_verifier: str,
        dpop_private_jwk_json: str,
        dpop_authserver_nonce: str,
        authserver_iss: str,
    ) -> Tuple[dict, str]:
        authserver_meta = self.fetch_authserver_meta(authserver_iss)

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": pkce_verifier,
        }
        token_url = authserver_meta["token_endpoint"]
        key = JsonWebKey.import_key(json.loads(dpop_private_jwk_json))

        resp, dpop_authserver_nonce = self._post_with_dpop_retry(
            token_url, params, key, nonce=dpop_authserver_nonce
        )
        resp.raise_for_status()

        return resp.json(), dpop_authserver_nonce

    def refresh_token(self, token: dict, client_id: str) -> Tuple[dict, str]:
        authserver_meta = self.fetch_authserver_meta(token["authserver_iss"])

        params = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": token["refresh_token"],
        }
        token_url = authserver_meta["token_endpoint"]
        key = JsonWebKey.import_key(json.loads(token["dpop_private_jwk"]))

        resp, dpop_authserver_nonce = self._post_with_dpop_retry(
            token_url, params, key, nonce=token["dpop_authserver_nonce"]
        )
        if resp.status_code not in (200, 201):
            logger.error("Token refresh failed with status %s.", resp.status_code)
        resp.raise_for_status()

        token_body = resp.json()
        token_body["dpop_authserver_nonce"] = dpop_authserver_nonce
        return token_body, dpop_authserver_nonce

    def pds_authed_request(
        self,
        method: str,
        url: str,
        token: dict,
        json_body: Optional[dict] = None,
        raw_data: Optional[bytes] = None,
        content_type: Optional[str] = None,
    ) -> Any:
        key = JsonWebKey.import_key(json.loads(token["dpop_private_jwk"]))
        dpop_pds_nonce = token.get("dpop_pds_nonce")
        access_token = token["access_token"]

        resp = None
        for _ in range(2):
            proof = self._pds_dpop_jwt(method, url, access_token, dpop_pds_nonce, key)
            headers = {"Authorization": f"DPoP {access_token}", "DPoP": proof}
            if content_type:
                headers["Content-Type"] = content_type

            with self.http.get_session() as sess:
                if raw_data is not None:
                    resp = sess.post(url, headers=headers, data=raw_data)
                else:
                    resp = sess.post(url, headers=headers, json=json_body)

            if (
                resp.status_code in (400, 401)
                and resp.json().get("error") == "use_dpop_nonce"
            ):
                dpop_pds_nonce = resp.headers["DPoP-Nonce"]
                logger.warning("Retrying PDS request with new DPoP nonce.")
                continue
            break

        return resp

    def upload_blob(self, token: dict, attachment: Attachment) -> dict:
        if attachment.mimetype not in SUPPORTED_IMAGE_MIMETYPES:
            raise AttachmentError(
                f"Unsupported attachment type '{attachment.mimetype}' for "
                f"'{attachment.filename}'; Bluesky posts only support image "
                f"embeds ({', '.join(sorted(SUPPORTED_IMAGE_MIMETYPES))})."
            )
        if len(attachment.data) > MAX_IMAGE_BYTES:
            raise AttachmentError(
                f"Attachment '{attachment.filename}' is {len(attachment.data)} bytes, "
                f"which exceeds Bluesky's {MAX_IMAGE_BYTES} byte limit per image."
            )

        url = f"{token['pds_url']}/xrpc/com.atproto.repo.uploadBlob"
        resp = self.pds_authed_request(
            "POST",
            url,
            token,
            raw_data=attachment.data,
            content_type=attachment.mimetype,
        )
        if resp.status_code not in (200, 201):
            logger.error(
                "Blob upload failed for '%s' with HTTP %s.",
                attachment.filename,
                resp.status_code,
            )
        resp.raise_for_status()
        return resp.json()["blob"]

    def build_images_embed(self, token: dict, attachments: List[Attachment]) -> dict:
        if len(attachments) > MAX_EMBED_IMAGES:
            raise AttachmentError(
                f"Bluesky posts support at most {MAX_EMBED_IMAGES} images, "
                f"got {len(attachments)}."
            )

        images = [
            {"image": self.upload_blob(token, attachment), "alt": attachment.filename}
            for attachment in attachments
        ]
        return {"$type": "app.bsky.embed.images", "images": images}

    def split_message_into_chunks(self, message: str) -> List[str]:
        """Split a message into chunks that fit within Bluesky's character limit."""
        max_length = self.credentials.CHARACTER_LIMIT
        if len(message) <= max_length:
            return [message]

        effective_max_length = max_length - self.credentials.THREAD_SUFFIX_RESERVE
        threads_required = math.ceil(len(message) / effective_max_length)
        chars_per_thread = math.ceil(len(message) / threads_required)

        return textwrap.wrap(message, chars_per_thread, break_long_words=False)

    def post_thread(
        self, token: dict, message: str, attachments: Optional[List[Attachment]] = None
    ) -> List[dict]:
        did = token["sub"]
        req_url = f"{token['pds_url']}/xrpc/com.atproto.repo.createRecord"
        chunks = self.split_message_into_chunks(message)
        embed = self.build_images_embed(token, attachments) if attachments else None

        thread_posts: List[dict] = []
        parent_post = None
        root_post = None
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        for i, chunk in enumerate(chunks):
            thread_text = (
                f"{chunk} ({i + 1}/{len(chunks)})" if len(chunks) > 1 else chunk
            )
            reply_to = (
                {"root": root_post, "parent": parent_post} if parent_post else None
            )
            body = create_post_payload(
                did, thread_text, now, reply_to, embed=embed if i == 0 else None
            )

            resp = self.pds_authed_request("POST", req_url, token=token, json_body=body)
            if resp.status_code not in (200, 201):
                logger.error("PDS returned HTTP %s while posting.", resp.status_code)
            resp.raise_for_status()

            post_data = resp.json()
            post_reference = {"uri": post_data["uri"], "cid": post_data["cid"]}
            thread_posts.append(post_reference)

            if i == 0:
                root_post = post_reference
            parent_post = post_reference
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        return thread_posts
