# SPDX-License-Identifier: GPL-3.0-only
"""Authorization requests in flight, kept until their code is exchanged."""

import sqlite3
from contextlib import closing
from typing import Any

from relaysms_adapter_sdk import AuthenticationError, state_dir

FILENAME = "oauth_session.db"
SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_sessions (
    request_identifier TEXT PRIMARY KEY,
    dpop_private_jwk TEXT NOT NULL,
    authserver_iss TEXT NOT NULL,
    dpop_authserver_nonce TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


def save(
    request_identifier: str,
    dpop_private_jwk: str,
    authserver_iss: str,
    dpop_authserver_nonce: str,
) -> None:
    with _connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO oauth_sessions (request_identifier, "
            "dpop_private_jwk, authserver_iss, dpop_authserver_nonce) "
            "VALUES (?, ?, ?, ?)",
            (
                request_identifier,
                dpop_private_jwk,
                authserver_iss,
                dpop_authserver_nonce,
            ),
        )


def get(request_identifier: str) -> dict[str, Any]:
    """Return the request's session.

    Raises:
        AuthenticationError: There's none, so the user has to start again.
    """
    with _connect() as db:
        row = db.execute(
            "SELECT dpop_private_jwk, authserver_iss, dpop_authserver_nonce "
            "FROM oauth_sessions WHERE request_identifier = ?",
            (request_identifier,),
        ).fetchone()
    if row is None:
        raise AuthenticationError("The authorization request expired; start again.")
    return dict(row)


def delete(request_identifier: str) -> None:
    with _connect() as db:
        db.execute(
            "DELETE FROM oauth_sessions WHERE request_identifier = ?",
            (request_identifier,),
        )


def _connect() -> closing[sqlite3.Connection]:
    db = sqlite3.connect(state_dir() / FILENAME, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute(SCHEMA)
    return closing(db)
