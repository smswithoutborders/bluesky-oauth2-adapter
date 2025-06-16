"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import json
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/oauth/client-metadata.json")
def oauth_client_metadata():
    """Every atproto OAuth client must have a public client metadata JSON document.
    It does not need to be at this specific path. The full URL to this file is the
    "client_id" of the app. This implementation dynamically uses the HTTP request
    Host name to infer the "client_id".
    """
    with open("credentials.json", "r", encoding="utf-8") as f:
        credentials = f.read()
        if not credentials:
            return jsonify({"error": "Credentials not found"}), 404

    return jsonify(json.loads(credentials))


@app.route("/oauth/callback")
def oauth_callback():
    """Endpoint for receiving "callback" responses from the Authorization Server,
    to complete the auth flow.
    """
    state = request.args["state"]
    authserver_iss = request.args["iss"]
    authorization_code = request.args["code"]

    print(f"State: {state}")
    print(f"Auth Server ISS: {authserver_iss}")
    print(f"Authorization Code: {authorization_code}")

    return None, 204  # No content response
