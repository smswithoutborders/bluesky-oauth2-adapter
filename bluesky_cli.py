"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import json
import click
from adapter import BlueskyOAuth2Adapter


def print_table(title, data: dict):
    divider = "=" * 40
    print(f"\n{divider}\n{title}\n{divider}")
    for k, v in data.items():
        print(
            f"{k:20}: {json.dumps(v, indent=2) if isinstance(v, (dict, list)) else v}"
        )
    print(divider)


@click.group
def cli():
    """Bluesky OAuth2 Adapter CLI."""


@cli.command("auth-url")
@click.option(
    "-p", "--pkce", is_flag=True, default=True, help="Auto-generate PKCE code verifier."
)
@click.option("-r", "--redirect", default=None, help="Redirect URI.")
@click.option("-s", "--state", default=None, help="OAuth2 state parameter.")
@click.option("-o", "--output", default=None, help="File to store the output as JSON.")
def auth_url(pkce, redirect, state, output):
    """Get the OAuth2 authorization URL."""
    adapter = BlueskyOAuth2Adapter()
    result = adapter.get_authorization_url(
        autogenerate_code_verifier=pkce,
        redirect_url=redirect,
        state=state,
    )
    print_table("Authorization URL Result", result)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"Output saved to {output}")


@cli.command("exchange")
@click.option("-c", "--code", required=True, help="Authorization code")
@click.option("-v", "--verifier", help="PKCE code verifier")
@click.option("-j", "--jwk", help="DPoP private JWK (JSON string)")
@click.option("-n", "--nonce", help="DPoP auth server nonce")
@click.option("-i", "--iss", help="Auth server issuer URL")
@click.option("-r", "--redirect", help="Redirect URI")
@click.option(
    "-o", "--output", default=None, help="File to read/write the output as JSON."
)
@click.option(
    "-f", "--input-file", default=None, help="File to read parameters from as JSON."
)
def exchange(code, verifier, jwk, nonce, iss, redirect, output, input_file):
    """Exchange code and fetch userinfo."""
    if input_file:
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                params = json.load(f)
            code = code or params.get("authorization_code")
            verifier = verifier or params.get("code_verifier")
            jwk = jwk or params.get("dpop_private_jwk")
            nonce = nonce or params.get("dpop_authserver_nonce")
            iss = iss or params.get("authserver_iss")
            redirect = redirect or params.get("redirect_uri")
        except FileNotFoundError:
            print(f"Input file {input_file} not found.")
            return

    adapter = BlueskyOAuth2Adapter()
    result = adapter.exchange_code_and_fetch_user_info(
        code=code,
        code_verifier=verifier,
        dpop_private_jwk=jwk,
        dpop_authserver_nonce=nonce,
        authserver_iss=iss,
        redirect_url=redirect,
    )
    print_table("Token Result", result.get("token", {}))
    print_table("User Info", result.get("userinfo", {}))

    if output:
        try:
            with open(output, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except FileNotFoundError:
            existing_data = {}

        existing_data.update(
            {"token": result.get("token", {}), "userinfo": result.get("userinfo", {})}
        )

        with open(output, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2)
        print(f"Output saved to {output}")


if __name__ == "__main__":
    cli()
