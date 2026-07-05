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

## Vercel version

Backend: `api/__wisp_rpc.js` using Upstash Redis / Vercel Redis-compatible REST credentials.
Static page: `index.html`.
Rewrite: `vercel.json` maps `/__wisp_rpc` to the API function.

Required environment variables in Vercel:

```txt
UPSTASH_REDIS_REST_URL
UPSTASH_REDIS_REST_TOKEN
```

Deploy this folder to Vercel after connecting an Upstash Redis database or equivalent Vercel Redis integration that provides those variables.
