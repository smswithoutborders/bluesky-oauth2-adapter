# Bluesky OAuth2 Platform Adapter

Lets [RelaySMS Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher) users post to their Bluesky account. Long messages become a thread, with up to four images on the first post. Built with the [RelaySMS Adapter SDK](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk).

## Settings

An atproto client is identified by its public [client metadata document](https://docs.bsky.app/docs/advanced-guides/oauth-client#client-and-server-metadata). The Publisher serves it at `/v1/platforms/bluesky/oauth/client-metadata.json`, built from the settings described in [adapter.toml](adapter.toml), so `client_id` is that URL. On a Publisher, an administrator sets them with its [settings commands](https://github.com/smswithoutborders/RelaySMS-Publisher/blob/main/docs/platforms.md#settings) or REST API.

## Develop

```bash
python3 -m venv venv
venv/bin/pip install -e '.[dev]'
venv/bin/pytest
```

To try it against Bluesky, use a [localhost client](https://atproto.com/specs/oauth#localhost-client-development), which needs no hosted metadata, then link an account and post with the [`relaysms-adapter`](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk#try-it) console:

```bash
venv/bin/relaysms-adapter config set \
  client_id="http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&scope=atproto%20transition%3Ageneric" \
  redirect_uris=http://127.0.0.1:8765/callback
venv/bin/relaysms-adapter link
venv/bin/relaysms-adapter send --attach ./photo.png
```
