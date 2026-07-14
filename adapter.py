# SPDX-License-Identifier: GPL-3.0-only

import base64
from typing import Any, Dict
from urllib.parse import urlencode

import requests
from authlib.common.security import generate_token
from authlib.jose import JsonWebKey

from atproto_client import (
    ATProtoClient,
    Attachment,
    AttachmentError,
    AuthServerError,
    is_safe_url,
    is_valid_did,
)
from config import Credentials, load_credentials
from logutils import get_logger
from protocol_interfaces import OAuth2ProtocolInterface
from session_store import SessionStore

logger = get_logger(__name__)


def _require(kwargs: dict, *fields: str) -> tuple:
    missing = [f for f in fields if not kwargs.get(f)]
    if missing:
        raise ValueError(f"Missing required parameter(s): {', '.join(missing)}")
    return tuple(kwargs[f] for f in fields)


class BlueskyOAuth2Adapter(OAuth2ProtocolInterface):
    """Adapter integrating Bluesky's OAuth2 protocol with RelaySMS."""

    def __init__(self):
        self.credentials: Credentials = load_credentials(self.config)
        self.atproto = ATProtoClient(self.credentials)
        self.sessions = SessionStore(self.credentials)

    def get_authorization_url(self, **kwargs) -> Dict[str, Any]:
        (request_identifier,) = _require(kwargs, "request_identifier")

        code_verifier = kwargs.get("code_verifier")
        autogenerate_code_verifier = kwargs.get("autogenerate_code_verifier", False)
        redirect_uri = kwargs.get("redirect_url") or self.credentials.redirect_uri
        base_path = kwargs.get("base_path")
        state = kwargs.get("state")

        if autogenerate_code_verifier and not code_verifier:
            code_verifier = generate_token(48)

        try:
            authserver_meta = self.atproto.fetch_authserver_meta()
        except Exception:
            logger.exception("Failed to fetch auth server metadata.")
            raise

        dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

        try:
            par_result = self.atproto.request_par(
                authserver_meta=authserver_meta,
                client_id=self.credentials.CLIENT_ID,
                redirect_uri=redirect_uri,
                scope=self.credentials.SCOPE,
                pkce_verifier=code_verifier,
                state=state,
                dpop_private_jwk=dpop_private_jwk,
            )
        except Exception:
            logger.exception("Failed to send PAR auth request.")
            raise

        auth_url = authserver_meta["authorization_endpoint"]
        if not is_safe_url(auth_url):
            logger.error("Insecure authorization endpoint returned by auth server.")
            raise AuthServerError("Insecure auth URL, please check the PDS URL.")

        qparam = urlencode(
            {
                "client_id": self.credentials.CLIENT_ID,
                "request_uri": par_result["request_uri"],
            }
        )
        authorization_url = f"{auth_url}?{qparam}"

        self.sessions.save(
            request_identifier=request_identifier,
            dpop_private_jwk=dpop_private_jwk.as_json(is_private=True),
            authserver_iss=self.credentials.PDS_URL,
            dpop_authserver_nonce=par_result.get("dpop_authserver_nonce"),
            base_path=base_path,
        )

        return {
            "authorization_url": authorization_url,
            "state": par_result.get("state"),
            "code_verifier": par_result.get("pkce_verifier"),
            "client_id": self.credentials.CLIENT_ID,
            "scope": self.credentials.SCOPE,
            "redirect_uri": redirect_uri,
        }

    def exchange_code_and_fetch_user_info(self, code: str, **kwargs) -> Dict[str, Any]:
        (request_identifier, code_verifier) = _require(
            kwargs, "request_identifier", "code_verifier"
        )
        redirect_uri = kwargs.get("redirect_url") or self.credentials.redirect_uri
        base_path = kwargs.get("base_path")

        session = self.sessions.get(request_identifier, base_path=base_path)
        authserver_iss = session["authserver_iss"] or self.credentials.PDS_URL

        tokens, dpop_authserver_nonce = self.atproto.exchange_code(
            client_id=self.credentials.CLIENT_ID,
            redirect_uri=redirect_uri,
            code=code,
            pkce_verifier=code_verifier,
            dpop_private_jwk_json=session["dpop_private_jwk"],
            dpop_authserver_nonce=session["dpop_authserver_nonce"],
            authserver_iss=authserver_iss,
        )

        if not is_valid_did(tokens["sub"]):
            raise ValueError("Invalid DID format returned by auth server.")

        account = self.atproto.resolve_account(tokens["sub"])
        if account["authserver_iss"] != authserver_iss:
            raise AuthServerError("Authorization server mismatch.")
        if self.credentials.SCOPE != tokens["scope"]:
            raise AuthServerError("Scope mismatch.")

        tokens.update(
            {
                "pds_url": account["pds_url"],
                "authserver_iss": account["authserver_iss"],
                "dpop_authserver_nonce": dpop_authserver_nonce,
                "dpop_private_jwk": session["dpop_private_jwk"],
            }
        )

        self.sessions.delete(request_identifier, base_path=base_path)

        return {
            "token": tokens,
            "userinfo": {"account_identifier": account["handle"]},
        }

    def revoke_token(self, token: dict, **_) -> bool:
        return True

    def send_message(self, token: dict, **kwargs) -> Dict[str, Any]:
        (message,) = _require(kwargs, "message")

        processed_attachments = []
        for idx, att_dict in enumerate(kwargs.get("attachments") or []):
            filename = att_dict.get("filename", f"attachment_{idx}")
            try:
                processed_attachments.append(
                    Attachment(
                        data=base64.b64decode(att_dict.get("data", "")),
                        filename=filename,
                        mimetype=att_dict.get("mimetype", ""),
                    )
                )
            except Exception as exc:
                raise ValueError(f"Invalid attachment data in '{filename}'.") from exc

        refreshed_token = token
        try:
            refreshed_body, dpop_authserver_nonce = self.atproto.refresh_token(
                token=token, client_id=self.credentials.CLIENT_ID
            )
            refreshed_token = {
                **refreshed_body,
                "dpop_authserver_nonce": dpop_authserver_nonce,
                "dpop_private_jwk": token["dpop_private_jwk"],
                "pds_url": token["pds_url"],
                "authserver_iss": token["authserver_iss"],
            }

            thread_posts = self.atproto.post_thread(
                refreshed_token, message, attachments=processed_attachments
            )
            logger.info("Successfully sent message with %d post(s).", len(thread_posts))
            return {"success": True, "refreshed_token": refreshed_token}

        except requests.exceptions.HTTPError as e:
            logger.exception("Failed to send message.")
            return {
                "success": False,
                "message": e.response.text,
                "refreshed_token": refreshed_token,
            }
        except AttachmentError as e:
            logger.exception("Failed to attach media.")
            return {
                "success": False,
                "message": str(e),
                "refreshed_token": refreshed_token,
            }
