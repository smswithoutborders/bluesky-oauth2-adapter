"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/oauth/client-metadata.json")
def oauth_client_metadata():
    """Every atproto OAuth client must have a public client metadata JSON document.
    It does not need to be at this specific path. The full URL to this file is the
    "client_id" of the app. This implementation dynamically uses the HTTP request
    Host name to infer the "client_id".
    """
    app_url = request.url_root.replace("http://", "https://")
    client_id = f"{app_url}oauth/client-metadata.json"

    return jsonify(
        {
            "client_id": client_id,
            "dpop_bound_access_tokens": True,
            "application_type": "web",
            "redirect_uris": [f"{app_url}oauth/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "atproto transition:generic",
            "token_endpoint_auth_method": None,
            "client_name": "Demo Bluesky OAuth2 Adapter.",
            "client_uri": app_url,
        }
    )


@app.route("/oauth/callback")
def oauth_callback():
    """Endpoint for receiving "callback" responses from the Authorization Server,
    to complete the auth flow.
    """
    state = request.args["state"]
    authserver_iss = request.args["iss"]
    authorization_code = request.args["code"]
