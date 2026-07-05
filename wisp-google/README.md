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

- Apps Script stores only encrypted offer/answer data temporarily.
- The chat messages travel through WebRTC DataChannel, not through Apps Script.
- Some networks may require TURN relay. This free version uses STUN only.
