# SPDX-License-Identifier: GPL-3.0-only

import os
import sqlite3
from typing import Any, Optional, Tuple

from atproto_client import ATProtoError
from config import Credentials
from logutils import get_logger

logger = get_logger(__name__)


class SessionStoreError(ATProtoError):
    """Raised when a stored OAuth session cannot be found or is invalid."""


def _db_query(
    db_path: str,
    schema_path: str,
    query: str,
    params: Optional[Tuple[Any, ...]] = None,
    first: bool = False,
) -> Any:
    if not os.path.exists(db_path):
        _initialize_database(db_path, schema_path)

    logger.debug("Executing query on database: %s", db_path)

    conn = None
    cursor = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        conn.commit()
        result = cursor.fetchall()

        if cursor.description is None:
            return None

        columns = [desc[0] for desc in cursor.description]
        if first:
            return dict(zip(columns, result[0])) if result else None

        return [dict(zip(columns, row)) for row in result]

    except sqlite3.Error:
        logger.exception("Database error while querying: %s", db_path)
        raise
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


def _initialize_database(db_path: str, schema_path: str) -> None:
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    logger.debug("Initializing database at %s using schema %s", db_path, schema_path)

    conn = None
    cursor = None
    try:
        with open(schema_path, "r", encoding="utf-8") as schema_file:
            schema_sql = schema_file.read()

        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.executescript(schema_sql)
        conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.Error:
        logger.exception("Database initialization error: %s", db_path)
        raise
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


class SessionStore:
    def __init__(self, credentials: Credentials):
        self.credentials = credentials

    def _paths(self, base_path: Optional[str]) -> Tuple[str, str]:
        db_path = self.credentials.db_path(base_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return str(db_path), str(self.credentials.schema_path())

    def save(
        self,
        request_identifier: str,
        dpop_private_jwk: str,
        authserver_iss: str,
        dpop_authserver_nonce: Optional[str],
        base_path: Optional[str] = None,
    ) -> None:
        db_path, schema_path = self._paths(base_path)
        _db_query(
            db_path,
            schema_path,
            "INSERT OR REPLACE INTO oauth_sessions "
            "(request_identifier, dpop_private_jwk, authserver_iss, dpop_authserver_nonce) "
            "VALUES (?, ?, ?, ?)",
            (
                request_identifier,
                dpop_private_jwk,
                authserver_iss,
                dpop_authserver_nonce,
            ),
        )

    def get(self, request_identifier: str, base_path: Optional[str] = None) -> dict:
        db_path, schema_path = self._paths(base_path)
        session = _db_query(
            db_path,
            schema_path,
            "SELECT dpop_private_jwk, authserver_iss, dpop_authserver_nonce "
            "FROM oauth_sessions WHERE request_identifier = ?",
            (request_identifier,),
            first=True,
        )
        if not session:
            raise SessionStoreError(
                f"No session found for request identifier: {request_identifier}"
            )
        return session

    def delete(self, request_identifier: str, base_path: Optional[str] = None) -> None:
        db_path, schema_path = self._paths(base_path)
        _db_query(
            db_path,
            schema_path,
            "DELETE FROM oauth_sessions WHERE request_identifier = ?",
            (request_identifier,),
        )
        logger.debug("Deleted OAuth session for request identifier.")
