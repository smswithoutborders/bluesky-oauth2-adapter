# SPDX-License-Identifier: GPL-3.0-only
"""The client metadata document, which is also the client's identity.

See https://atproto.com/specs/oauth for its fields.
"""

from dataclasses import dataclass

from relaysms_adapter_sdk import read_config

DEFAULT_PDS_URL = "https://bsky.social"
DEFAULT_SCOPE = "atproto transition:generic"


@dataclass(frozen=True)
class Credentials:
    client_id: str
    redirect_uri: str
    scope: str = DEFAULT_SCOPE
    pds_url: str = DEFAULT_PDS_URL


def load() -> Credentials:
    """Read credentials.json from the adapter's config directory.

    Raises:
        ValueError: The file is invalid.
    """
    raw = read_config()
    if not isinstance(raw.get("client_id"), str) or not raw["client_id"].strip():
        raise ValueError("client_id in credentials.json must be a non-empty string.")
    redirect_uris = raw.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ValueError("redirect_uris in credentials.json must be a non-empty list.")

    return Credentials(
        client_id=raw["client_id"],
        redirect_uri=redirect_uris[0],
        scope=raw.get("scope", DEFAULT_SCOPE),
        pds_url=raw.get("pds_url", DEFAULT_PDS_URL),
    )
