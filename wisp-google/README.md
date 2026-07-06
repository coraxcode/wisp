# Wisp - Google Apps Script + CacheService - stable v3

This version replaces the manual offer/answer exchange with Google Apps Script temporary signaling.

Files:

- Code.gs
- index.html

Important:

- In Google Apps Script, create an HTML file named exactly `index`.
- Paste `index.html` into that file.
- Paste `Code.gs` into `Code.gs`.
- Deploy as Web app.
- Execute as: Me.
- Who has access: Anyone.

Quick test:

Open:

`YOUR_WEB_APP_URL/exec?health=1`

Expected result:

`{"ok":true,"service":"wisp-gas-cache-signal","version":1}`

Then open the normal `/exec` URL and click `Create private room`.
The generated invite must start with:

`https://script.google.com/macros/s/.../exec#r=...`

It must not start with:

`https://n-...googleusercontent.com/userCodeAppPanel#r=...`

Notes:

Notes:

- In WebRTC mode, Apps Script stores only encrypted offer/answer setup data temporarily.
- In WebRTC mode, chat text travels through WebRTC DataChannel and does not pass through Apps Script.
- In Tor Mode, WebRTC is disabled and Apps Script relays only temporary end-to-end encrypted message blobs.
- Manual Pairing can be used without sending setup data to Apps Script.
- STUN is available for compatibility, and relay-only mode can use a user-provided TURN server.
- Apps Script never receives the URL fragment secret `#k=...`, the optional password, or plaintext chat text.
