# Wisp multi-platform signaling

This package keeps the browser app universal. The same `index.html` first uses Google Apps Script (`google.script.run`) when it exists; otherwise it calls `POST /__wisp_rpc`.

The servers below implement the same RPC methods used by the app:

- `gasCreateRoom`
- `gasGetOffer`
- `gasSetAnswer`
- `gasGetAnswer`
- `gasDeleteRoom`
- `gasHealth`

Security model: the server only receives encrypted WebRTC setup blobs. It never receives the URL fragment secret `#k=...`, the password, or plaintext chat.

## Cloudflare version

Backend: `worker.js` with Durable Object storage.
Static page: `public/index.html`.

Deploy:

```bash
npm install -g wrangler
wrangler deploy
```

The Worker serves the page and handles `POST /__wisp_rpc`.
