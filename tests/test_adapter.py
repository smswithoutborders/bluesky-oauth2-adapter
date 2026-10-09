# SPDX-License-Identifier: GPL-3.0-only

import json
from unittest.mock import MagicMock

import pytest
import requests
from relaysms_adapter_sdk import (
    Account,
    Attachment,
    AuthenticationError,
    AuthorizationRequest,
    CodeExchangeRequest,
    InvalidParamsError,
    Message,
    RateLimitedError,
    SendRequest,
    TokenInvalidError,
    UpstreamError,
)
from relaysms_adapter_sdk.paths import CONFIG_DIR_ENV, STATE_DIR_ENV

from bluesky_oauth2_adapter import BlueskyAdapter
from bluesky_oauth2_adapter.atproto_client import AttachmentError, split_message

SCOPE = "atproto transition:generic"
DID = "did:plc:abc123"
# The token shape the adapter has always stored.
TOKEN = {
    "access_token": "access",
    "refresh_token": "refresh",
    "sub": DID,
    "scope": SCOPE,
    "pds_url": "https://pds.example",
    "authserver_iss": "https://bsky.social",
    "dpop_authserver_nonce": "n0",
    "dpop_private_jwk": "{}",
}


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    monkeypatch.setenv(CONFIG_DIR_ENV, str(tmp_path))
    monkeypatch.setenv(STATE_DIR_ENV, str(tmp_path / "state"))
    (tmp_path / "credentials.json").write_text(
        json.dumps(
            {
                "client_id": "https://app/client-metadata.json",
                "redirect_uris": ["https://app/callback"],
                "scope": SCOPE,
            }
        )
    )
    adapter = BlueskyAdapter()
    adapter.atproto = MagicMock()
    return adapter


def http_error(status):
    response = requests.Response()
    response.status_code = status
    return requests.HTTPError(response=response)


def link(adapter, code="c"):
    atproto = adapter.atproto
    atproto.fetch_authserver_meta.return_value = {
        "authorization_endpoint": "https://bsky.social/oauth/authorize"
    }
    atproto.request_par.return_value = {
        "request_uri": "urn:par",
        "state": "s",
        "dpop_authserver_nonce": "n1",
    }
    auth = adapter.create_authorization_url(
        AuthorizationRequest(state="s", code_verifier="v", request_identifier="r1")
    )
    atproto.exchange_code.return_value = (
        {"access_token": "a", "refresh_token": "r", "sub": DID, "scope": SCOPE},
        "n2",
    )
    atproto.resolve_account.return_value = {
        "handle": "me.bsky.social",
        "pds_url": "https://pds.example",
        "authserver_iss": "https://bsky.social",
    }
    account = adapter.exchange_code(
        CodeExchangeRequest(code=code, code_verifier="v", request_identifier="r1")
    )
    return auth, account


class TestLink:
    def test_authorization_url_and_account(self, adapter):
        auth, account = link(adapter)
        assert auth.url == (
            "https://bsky.social/oauth/authorize?client_id="
            "https%3A%2F%2Fapp%2Fclient-metadata.json&request_uri=urn%3Apar"
        )
        assert account.identifier == "me.bsky.social"
        assert account.token["dpop_authserver_nonce"] == "n2"
        assert account.token["pds_url"] == "https://pds.example"
        kwargs = adapter.atproto.exchange_code.call_args.kwargs
        assert kwargs["dpop_authserver_nonce"] == "n1"

    def test_session_is_single_use(self, adapter):
        link(adapter)
        with pytest.raises(AuthenticationError, match="start again"):
            adapter.exchange_code(
                CodeExchangeRequest(
                    code="c", code_verifier="v", request_identifier="r1"
                )
            )

    def test_needs_request_identifier_and_verifier(self, adapter):
        with pytest.raises(InvalidParamsError):
            adapter.create_authorization_url(AuthorizationRequest(code_verifier="v"))

    def test_rejected_code(self, adapter):
        adapter.atproto.exchange_code.side_effect = http_error(400)
        with pytest.raises(AuthenticationError):
            link(adapter)


class TestSendMessage:
    def send(self, adapter, attachments=()):
        adapter.atproto.refresh_token.return_value = (
            {**TOKEN, "access_token": "new", "refresh_token": "new-refresh"},
            "n9",
        )
        return adapter.send_message(
            SendRequest(
                Message(body="hi", attachments=attachments),
                Account("me", token=TOKEN),
            )
        )

    def test_returns_rotated_token(self, adapter):
        adapter.atproto.post_thread.return_value = [{}]
        result = self.send(adapter)
        assert result.token["refresh_token"] == "new-refresh"
        assert result.token["dpop_authserver_nonce"] == "n9"
        assert result.token["dpop_private_jwk"] == "{}"

    def test_failed_post_keeps_rotated_token(self, adapter):
        adapter.atproto.post_thread.side_effect = http_error(500)
        with pytest.raises(UpstreamError) as e:
            self.send(adapter)
        assert e.value.data["token"]["refresh_token"] == "new-refresh"

    def test_rate_limited(self, adapter):
        adapter.atproto.post_thread.side_effect = http_error(429)
        with pytest.raises(RateLimitedError):
            self.send(adapter)

    def test_bad_attachment(self, adapter):
        adapter.atproto.post_thread.side_effect = AttachmentError("not an image")
        with pytest.raises(InvalidParamsError, match="not an image"):
            self.send(adapter, (Attachment(b"x", "a.pdf", "application/pdf"),))

    def test_refused_refresh(self, adapter):
        adapter.atproto.refresh_token.side_effect = http_error(400)
        with pytest.raises(TokenInvalidError):
            adapter.send_message(
                SendRequest(Message(body="hi"), Account("me", token=TOKEN))
            )


def test_split_message():
    assert split_message("short") == ["short"]
    assert all(len(post) <= 290 for post in split_message("word " * 200))
