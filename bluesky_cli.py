"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import click
from adapter import BlueskyOAuth2Adapter


@click.group
def cli():
    """Bluesky OAuth2 Adapter CLI."""


@cli.command("get-auth-url")
@click.option(
    "--autogenerate-code-verifier",
    "-a",
    is_flag=True,
    default=True,
    help="Auto-generate PKCE code verifier.",
)
@click.option("--redirect-url", "-r", default=None, help="Override redirect URI.")
@click.option("--state", "-s", default=None, help="State parameter for OAuth2.")
def get_auth_url(autogenerate_code_verifier, redirect_url, state):
    """Get the OAuth2 authorization URL."""
    adapter = BlueskyOAuth2Adapter()
    result = adapter.get_authorization_url(
        autogenerate_code_verifier=autogenerate_code_verifier,
        redirect_url=redirect_url,
        state=state,
    )
    click.echo(f"Authorization URL: {result['authorization_url']}")
    click.echo(f"State: {result['state']}")
    click.echo(f"Code Verifier: {result['code_verifier']}")
    click.echo(f"Client ID: {result['client_id']}")
    click.echo(f"Scope: {result['scope']}")
    click.echo(f"Redirect URI: {result['redirect_uri']}")


if __name__ == "__main__":
    cli()
