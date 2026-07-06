# Wisp for Vercel + Upstash Redis

This folder deploys the current Wisp browser app with WebRTC mode and Tor Mode.

## Files

```txt
index.html
vercel.json
api/__wisp_rpc.js
```

`index.html` automatically calls `POST /__wisp_rpc` when it is not running inside Google Apps Script. `vercel.json` rewrites `/__wisp_rpc` to the Vercel function.

## Required environment variables

Create an Upstash Redis database, then add these Vercel environment variables:

```txt
UPSTASH_REDIS_REST_URL
UPSTASH_REDIS_REST_TOKEN
```

## Deploy

```bash
vercel deploy
```

## Security model

The server stores only encrypted setup blobs and, in Tor Mode, encrypted message blobs. It never receives the URL fragment secret `#k=...`, the optional password, or plaintext chat text.

## Health check

Open the site, then test:

```txt
POST /__wisp_rpc
{ "method": "gasHealth", "args": [] }
```
