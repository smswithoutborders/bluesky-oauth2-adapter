# SPDX-License-Identifier: GPL-3.0-only

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override
from urllib.parse import urlencode

import requests
from authlib.jose import JsonWebKey
from relaysms_adapter_sdk import (
    Account,
    AdapterError,
    AuthenticationError,
    AuthorizationRequest,
    AuthorizationUrl,
    CodeExchangeRequest,
    InvalidParamsError,
    OAuth2Adapter,
    RateLimitedError,
    RevokeRequest,
    SendRequest,
    SendResult,
    TokenInvalidError,
    UpstreamError,
)

from bluesky_oauth2_adapter import credentials, session_store
from bluesky_oauth2_adapter.atproto_client import (
    ATProtoClient,
    ATProtoError,
    AttachmentError,
    AuthServerError,
    is_safe_url,
    is_valid_did,
)

logger = logging.getLogger(__name__)


class BlueskyAdapter(OAuth2Adapter):
    def __init__(self) -> None:
        self.credentials = credentials.load()
        self.atproto = ATProtoClient(self.credentials)

    @override
    def create_authorization_url(
        self, request: AuthorizationRequest
    ) -> AuthorizationUrl:
        if not request.request_identifier or not request.code_verifier:
            raise InvalidParamsError(
                "request_identifier and code_verifier are required."
            )
        redirect_uri = request.redirect_url or self.credentials.redirect_uri
        dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

        with _upstream():
            authserver_meta = self.atproto.fetch_authserver_meta()
            par = self.atproto.request_par(
                authserver_meta=authserver_meta,
                client_id=self.credentials.client_id,
                redirect_uri=redirect_uri,
                scope=self.credentials.scope,
                pkce_verifier=request.code_verifier,
                state=request.state,
                dpop_private_jwk=dpop_private_jwk,
            )
        auth_url = authserver_meta["authorization_endpoint"]
        if not is_safe_url(auth_url):
            raise UpstreamError("The auth server returned an insecure URL.")

        session_store.save(
            request_identifier=request.request_identifier,
            dpop_private_jwk=dpop_private_jwk.as_json(is_private=True),
            authserver_iss=self.credentials.pds_url,
            dpop_authserver_nonce=par["dpop_authserver_nonce"],
        )
        query = urlencode(
            {"client_id": self.credentials.client_id, "request_uri": par["request_uri"]}
        )
        return AuthorizationUrl(
            url=f"{auth_url}?{query}",
            state=par["state"],
            code_verifier=request.code_verifier,
            client_id=self.credentials.client_id,
            scope=self.credentials.scope,
            redirect_url=redirect_uri,
        )

    @override
    def exchange_code(self, request: CodeExchangeRequest) -> Account:
        if not request.request_identifier or not request.code_verifier:
            raise InvalidParamsError(
                "request_identifier and code_verifier are required."
            )
        session = session_store.get(request.request_identifier)
        authserver_iss = session["authserver_iss"] or self.credentials.pds_url

        with _upstream(rejected=AuthenticationError):
            tokens, dpop_authserver_nonce = self.atproto.exchange_code(
                client_id=self.credentials.client_id,
                redirect_uri=request.redirect_url or self.credentials.redirect_uri,
                code=request.code,
                pkce_verifier=request.code_verifier,
                dpop_private_jwk_json=session["dpop_private_jwk"],
                dpop_authserver_nonce=session["dpop_authserver_nonce"],
                authserver_iss=authserver_iss,
            )
            if not is_valid_did(tokens["sub"]):
                raise AuthServerError("The auth server returned an invalid DID.")
            account = self.atproto.resolve_account(tokens["sub"])
        if account["authserver_iss"] != authserver_iss:
            raise AuthenticationError("The account uses a different auth server.")
        if tokens["scope"] != self.credentials.scope:
            raise AuthenticationError("Access wasn't granted to every scope.")

        session_store.delete(request.request_identifier)
        token = {
            **tokens,
            "pds_url": account["pds_url"],
            "authserver_iss": account["authserver_iss"],
            "dpop_authserver_nonce": dpop_authserver_nonce,
            "dpop_private_jwk": session["dpop_private_jwk"],
        }
        return Account(identifier=account["handle"], token=token)

    @override
    def send_message(self, request: SendRequest) -> SendResult:
        if request.account is None or request.account.token is None:
            raise InvalidParamsError("Bluesky posts only from a linked account.")
        token = request.account.token

        with _upstream(rejected=TokenInvalidError):
            body, dpop_authserver_nonce = self.atproto.refresh_token(
                token=token, client_id=self.credentials.client_id
            )
        # Refresh tokens are single use, so the new one must reach the Publisher
        # even when posting fails.
        token = {
            **body,
            "dpop_authserver_nonce": dpop_authserver_nonce,
            "dpop_private_jwk": token["dpop_private_jwk"],
            "pds_url": token["pds_url"],
            "authserver_iss": token["authserver_iss"],
        }
        try:
            with _upstream():
                posts = self.atproto.post_thread(
                    token, request.message.body, list(request.message.attachments)
                )
        except AdapterError as e:
            e.data = {**(e.data or {}), "token": token}
            raise
        logger.info("Posted %d post(s).", len(posts))
        return SendResult(token=token)

    @override
    def revoke(self, request: RevokeRequest) -> None:
        # Bluesky tokens expire on their own; there's nothing to revoke yet.
        return None


@contextmanager
def _upstream(rejected: type[AdapterError] = UpstreamError) -> Iterator[None]:
    """Map AT Protocol and HTTP failures to AdapterErrors.

    rejected is raised when the server refuses the request itself.
    """
    try:
        yield
    except AttachmentError as e:
        raise InvalidParamsError(str(e)) from e
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else None
        if status == 429:
            raise RateLimitedError("Bluesky is rate limiting requests.") from e
        if status in {400, 401, 403}:
            raise rejected(f"Bluesky refused the request: {status}") from e
        raise UpstreamError(f"Bluesky failed: {e}") from e
    except (ATProtoError, requests.RequestException) as e:
        raise UpstreamError(f"Bluesky failed: {e}") from e
