# Bluesky OAuth2 Platform Adapter

This adapter provides a pluggable implementation for integrating Bluesky as a messaging platform. It is designed to work with [RelaySMS Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher), enabling users to connect to Bluesky using OAuth2 authentication.

## Requirements

- **Python**: Version >=
  [3.8.10](https://www.python.org/downloads/release/python-3810/)
- **Python Virtual Environments**:
  [Documentation](https://docs.python.org/3/tutorial/venv.html)

## Dependencies

### On Ubuntu

Install the necessary system packages:

```bash
sudo apt install build-essential python3-dev
```

## Installation

1. **Create a virtual environment:**

   ```bash
   python3 -m venv venv
   ```

2. **Activate the virtual environment:**

   ```bash
   . venv/bin/activate
   ```

3. **Install the required Python packages:**

   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. **Host your client metadata JSON document:**  
   Every atproto OAuth client must publish a client metadata JSON document on a publicly accessible URL.

   - The `client_id` is the full `https://` URL where this JSON document is hosted.
   - For more details, see the [atproto OAuth client documentation](https://docs.bsky.app/docs/advanced-guides/oauth-client#client-and-server-metadata).

2. **Configure the credentials file path:**
   - In your `config.ini`, set the path to your `credentials.json` file as shown below:

```ini
   [credentials]
   path = ./credentials.json
```

3. **Create your `credentials.json` file:**
   - This file should contain your client metadata.
   - Below is an example of what your `credentials.json` might look like:

**Sample `credentials.json`**

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "application_type": "web",
  "client_name": "Demo Bluesky OAuth2 Adapter.",
  "client_uri": "https://app.example.com",
  "dpop_bound_access_tokens": true,
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["https://app.example.com/oauth/callback"],
  "response_types": ["code"],
  "scope": "atproto transition:generic",
  "token_endpoint_auth_method": "none"
}
```

## TODO

- Support additional PDS providers beyond just https://bsky.social
