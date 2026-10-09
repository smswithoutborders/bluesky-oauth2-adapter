# Bluesky OAuth2 Platform Adapter

Lets [RelaySMS Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher) users post to their Bluesky account. Long messages become a thread, with up to four images on the first post. Built with the [RelaySMS Adapter SDK](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk).

## Credentials

An atproto client is identified by its public [client metadata document](https://docs.bsky.app/docs/advanced-guides/oauth-client#client-and-server-metadata): `client_id` is the `https://` URL it's served at. Put the document in the adapter's config directory as `credentials.json`; the Publisher keeps it at `data/platforms/config/<adapter id>/credentials.json` and serves it at `/v1/platforms/bluesky/oauth/client-metadata.json`.

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

Add `"pds_url"` to use an auth server other than `https://bsky.social`.

## Develop

```bash
python3 -m venv venv
venv/bin/pip install -e '.[dev]'
venv/bin/pytest
```

To try it against Bluesky, use a [localhost client](https://atproto.com/specs/oauth#localhost-client-development), which needs no hosted metadata. Put this in `.relaysms/config/credentials.json`:

```json
{
  "client_id": "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&scope=atproto%20transition%3Ageneric",
  "redirect_uris": ["http://127.0.0.1:8765/callback"]
}
```

Then link an account and post with the [`relaysms-adapter`](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk#try-it) console:

```bash
venv/bin/relaysms-adapter link
venv/bin/relaysms-adapter send --attach ./photo.png
```
