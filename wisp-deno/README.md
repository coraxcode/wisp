# Wisp for Deno Deploy + Deno KV

This folder deploys the current Wisp browser app with WebRTC mode and Tor Mode.

## Files

```txt
index.html
main.ts
deno.json
```

`main.ts` serves the static page and handles `POST /__wisp_rpc` using Deno KV.

## Local test

```bash
deno task start
```

Then open the local URL printed by Deno.

## Deploy

Deploy this folder to Deno Deploy and attach/enable Deno KV for the project.

## Security model

The server stores only encrypted setup blobs and, in Tor Mode, encrypted message blobs. It never receives the URL fragment secret `#k=...`, the optional password, or plaintext chat text.
