# SPDX-License-Identifier: GPL-3.0-only

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from logutils import get_logger

logger = get_logger(__name__)

DEFAULT_PDS_URL = "https://bsky.social"
DEFAULT_SCOPE = "atproto transition:generic"
DEFAULT_SESSIONS_DIRNAME = "sessions"
DEFAULT_DB_FILENAME = "oauth_session.db"
DEFAULT_SCHEMA_FILENAME = "schema.sql"
DEFAULT_CHARACTER_LIMIT = 300
DEFAULT_THREAD_SUFFIX_RESERVE = 10
DEFAULT_AUTHSERVER_DPOP_TTL = 30
DEFAULT_PDS_DPOP_TTL = 10


@dataclass
class Credentials:
    """see https://atproto.com/specs/oauth for AT Protocol OAuth
    client metadata)."""

    CLIENT_ID: str
    REDIRECT_URIS: List[str]
    SCOPE: str = DEFAULT_SCOPE
    PDS_URL: str = DEFAULT_PDS_URL

    SESSIONS_DIR: Optional[str] = None
    DB_FILENAME: str = DEFAULT_DB_FILENAME
    SCHEMA_FILENAME: str = DEFAULT_SCHEMA_FILENAME

    CHARACTER_LIMIT: int = DEFAULT_CHARACTER_LIMIT
    THREAD_SUFFIX_RESERVE: int = DEFAULT_THREAD_SUFFIX_RESERVE

    AUTHSERVER_DPOP_TTL: int = DEFAULT_AUTHSERVER_DPOP_TTL
    PDS_DPOP_TTL: int = DEFAULT_PDS_DPOP_TTL

    _package_dir: Path = field(default=Path(__file__).parent, repr=False, compare=False)

    @property
    def redirect_uri(self) -> str:
        return self.REDIRECT_URIS[0]

    @property
    def scopes(self) -> List[str]:
        return self.SCOPE.split()

    def sessions_dir(self, base_path: Optional[str] = None) -> Path:
        if base_path:
            return Path(base_path).expanduser()
        if self.SESSIONS_DIR:
            return Path(self.SESSIONS_DIR).expanduser()
        return self._package_dir / DEFAULT_SESSIONS_DIRNAME

    def db_path(self, base_path: Optional[str] = None) -> Path:
        return self.sessions_dir(base_path) / self.DB_FILENAME

    def schema_path(self) -> Path:
        return self._package_dir / self.SCHEMA_FILENAME


_REQUIRED_FIELDS = {"client_id", "redirect_uris"}


def _resolve_creds_path(configs: Dict[str, Any]) -> Path:
    creds_config = configs.get("credentials", {})
    raw_path = creds_config.get("path", "")
    if not raw_path:
        raise ValueError("Missing 'credentials.path' in configuration.")

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path(__file__).parent / path
    return path


def _validate_creds(creds: Dict[str, Any]) -> None:
    missing = _REQUIRED_FIELDS - creds.keys()
    if missing:
        raise ValueError(
            f"Missing required credential fields: {', '.join(sorted(missing))}"
        )

    if not isinstance(creds["client_id"], str) or not creds["client_id"].strip():
        raise ValueError("'client_id' must be a non-empty string.")

    redirect_uris = creds["redirect_uris"]
    if (
        not isinstance(redirect_uris, list)
        or not redirect_uris
        or not all(isinstance(uri, str) and uri.strip() for uri in redirect_uris)
    ):
        raise ValueError("'redirect_uris' must be a non-empty list of strings.")

    for optional_str_field in ("scope", "pds_url", "sessions_dir"):
        if optional_str_field in creds and (
            not isinstance(creds[optional_str_field], str)
            or not creds[optional_str_field].strip()
        ):
            raise ValueError(
                f"'{optional_str_field}' must be a non-empty string when provided."
            )


def load_credentials(configs: Dict[str, Any]) -> Credentials:
    """Load, validate, and return a Credentials instance from the specified path."""
    path = _resolve_creds_path(configs)
    logger.debug("Loading credentials from %s", path)

    try:
        with path.open(encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Credentials file not found: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Credentials file is not valid JSON: {e}")

    _validate_creds(raw)

    return Credentials(
        CLIENT_ID=raw["client_id"],
        REDIRECT_URIS=raw["redirect_uris"],
        SCOPE=raw.get("scope", DEFAULT_SCOPE),
        PDS_URL=raw.get("pds_url", DEFAULT_PDS_URL),
        SESSIONS_DIR=raw.get("sessions_dir"),
    )
