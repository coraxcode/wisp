# Wisp for Cloudflare Workers + Durable Objects

This folder deploys the current Wisp browser app with WebRTC mode and Tor Mode.

## Files

```txt
worker.js
wrangler.toml
public/index.html
```

The Worker serves `public/index.html` and handles `POST /__wisp_rpc`. Room state is stored inside a Durable Object named `WispRoom`.

## Deploy

```bash
npx wrangler deploy
```

## Local test

```bash
npx wrangler dev
```

## Security model

The server stores only encrypted setup blobs and, in Tor Mode, encrypted message blobs. It never receives the URL fragment secret `#k=...`, the optional password, or plaintext chat text.
