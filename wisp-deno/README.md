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

## Deno Deploy version

Backend: `main.ts` with Deno KV.
Static page: `index.html`.

Local test:

```bash
deno task start
```

Deploy this folder to Deno Deploy and attach/enable a Deno KV database for the project.
