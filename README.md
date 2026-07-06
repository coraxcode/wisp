# Wisp multi-platform signaling

This package keeps the browser app universal. The same `index.html` first uses Google Apps Script (`google.script.run`) when it exists; otherwise it calls `POST /__wisp_rpc`.

The servers below implement the same RPC methods used by the app:

- `gasCreateRoom`
- `gasGetOffer`
- `gasSetAnswer`
- `gasGetAnswer`
- `gasDeleteRoom`
- `gasHealth`
- `gasTorCreateRoom`
- `gasTorJoinRoom`
- `gasTorSend`
- `gasTorPoll`
- `gasTorDeleteRoom`

Security model: in WebRTC mode, the server only receives encrypted setup blobs. In Tor Mode, the server also relays temporary end-to-end encrypted message blobs. The server never receives the URL fragment secret `#k=...`, the optional password, or plaintext chat text.

## Folders

- `wisp-google/` -> Google Script
- `wisp-cloudflare/` -> Cloudflare Worker + Durable Object
- `wisp-deno/` -> Deno Deploy + Deno KV
- `wisp-vercel/` -> Vercel API Function + Upstash Redis/Vercel Redis-compatible REST

Each folder contains its own copy of the universal `index.html`.
