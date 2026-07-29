# SPDX-License-Identifier: GPL-3.0-only
"""
Interactive test client for the Bluesky OAuth2 adapter.

Run it with:

    python -m tests.client
"""

import base64
import cmd
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

SESSION_FILE = Path(__file__).parent / "session.json"


def _load_token() -> Optional[Dict[str, Any]]:
    try:
        with SESSION_FILE.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def _save_token(token: Dict[str, Any]) -> None:
    with SESSION_FILE.open("w", encoding="utf-8") as f:
        json.dump(token, f, indent=2)


def _clear_token() -> None:
    SESSION_FILE.unlink(missing_ok=True)


class BlueskyAdapterClient(cmd.Cmd):
    intro = "Bluesky adapter test client. Type help or ? for a list of commands."
    prompt = "adapter> "

    def __init__(self, adapter):
        super().__init__()
        self.adapter = adapter
        self.token = _load_token()
        self.request_identifier = None
        self.code_verifier = None

    def _call(self, fn, *args, on_success=None, **kwargs):
        """Invoke an adapter method, pretty-print the result, and run an
        optional on_success(result) callback for side effects like updating
        the stored token. Adapter errors are caught and printed, not raised,
        so the REPL keeps running.
        """
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            print(f"Error: {e}")
            return
        print(json.dumps(result, indent=2))
        if on_success:
            on_success(result)

    def do_auth_url(self, line):
        """auth_url [request_identifier] - Generate the OAuth2 authorization URL.
        Auto-generates a request_identifier if none is given."""
        request_identifier = line.strip() or base64.b64encode(os.urandom(32)).decode(
            "utf-8"
        )

        def store_session(result):
            self.request_identifier = request_identifier
            self.code_verifier = result.get("code_verifier")

        self._call(
            self.adapter.get_authorization_url,
            request_identifier=request_identifier,
            autogenerate_code_verifier=True,
            on_success=store_session,
        )

    def do_exchange(self, line):
        """exchange <code> - Exchange an authorization code for a token and user info.
        Uses the request_identifier/code_verifier from the last auth_url call."""
        code = line.strip()
        if not code:
            print("Usage: exchange <code>")
            return
        if self.request_identifier is None:
            print("No pending session. Run 'auth_url' first.")
            return

        def store_token(result):
            if "token" in result:
                self.token = result["token"]
                _save_token(self.token)

        self._call(
            self.adapter.exchange_code_and_fetch_user_info,
            code,
            request_identifier=self.request_identifier,
            code_verifier=self.code_verifier,
            on_success=store_token,
        )

    def do_send_message(self, line):
        """send_message <message> - Send a message using the stored token."""
        message = line.strip()
        if not message:
            print("Usage: send_message <message>")
            return
        if self.token is None:
            print("No token stored. Run 'exchange <code>' first.")
            return

        def update_token(result):
            if result.get("refreshed_token"):
                self.token = result["refreshed_token"]
                _save_token(self.token)

        self._call(
            self.adapter.send_message,
            token=self.token,
            message=message,
            on_success=update_token,
        )

    def do_revoke(self, line):
        """revoke - Revoke the stored token."""
        if self.token is None:
            print("No token stored. Run 'exchange <code>' first.")
            return

        def clear_token(result):
            if result:
                self.token = None
                _clear_token()

        self._call(self.adapter.revoke_token, token=self.token, on_success=clear_token)

    def do_quit(self, _):
        """Exit the client."""
        return True

    do_EOF = do_quit


if __name__ == "__main__":
    from adapter import BlueskyOAuth2Adapter

    BlueskyAdapterClient(BlueskyOAuth2Adapter()).cmdloop()
