# Wisp Manual — How the Program Works

*A short, simple guide. It describes the Google Apps Script setup (`Code.gs` + `index.html`), but the same philosophy applies to the other platforms (Vercel, Deno, Cloudflare) — only the "vault" where messages are briefly stored changes.*

---

## 1. What Wisp Is, in One Sentence

Wisp is a **private live chat between two people**, where your text appears on the other person's screen **letter by letter**, disappears on its own, and travels **end-to-end encrypted** — meaning not even the server can read what you write.

Think of a **secret note**: you write it, the other person reads it, and the paper dissolves a few seconds later.

---

## 2. The Two Pieces of the Program

Wisp has only two parts, and it's important to understand the role of each:

**The page (`index.html`) — where everything actually happens.**
This is the program itself, running in each person's browser. It is what scrambles (encrypts) and unscrambles the messages. **The secret key that unlocks the messages never leaves here.**

**The server (`Code.gs`) — the "dumb mail carrier."**
It does just one thing: hold a **sealed envelope** for a few minutes and hand it to the other person. It **never receives the key**, so it **cannot open the envelope**. It's like a mail carrier who delivers sealed letters without ever being able to read them.

> 🔑 The core idea: all the secret work is done in the two browsers. The server is just a temporary meeting point. That's why security does not depend on "trusting the server."

---

## 3. How Two People Connect (the "Handshake")

1. **You create a room.** The browser generates a secret key and an invite. The invite (a **link**) already carries the key hidden inside it, in the part after the `#`.
2. **You send the link** to the other person however you like (WhatsApp, email…).
3. **The other person opens the link.** Their browser reads the key that was in the `#` and replies.
4. **Done, connected.** From there on, the text travels directly between you two, live.

> An important and clever detail: the part of the link after the `#` (where the key lives) is **never sent to the server** — that's a rule built into browsers themselves. That's why the "mail carrier" never sees the key, even while delivering the invite.

---

## 4. The Three Connection Modes (what each checkbox does)

When you create the room, you choose **how** the two computers will talk to each other. From fastest to most private:

**Normal / compatibility mode (the "STUN" box).**
The two talk almost directly. It's the fastest. However, in this mode the two exchange each other's **internet address (IP)** in order to find one another.

**"Hide my IP" mode (the "relay-only" box).**
Here the conversation passes through an **intermediary (a TURN server)**. The other person only sees that intermediary's address, **never your real IP**. It's more private, a little slower, and requires you to configure a relay service (you can type the details right on the screen).

**Tor mode (the "Tor" box).**
The most anonymous. Here there is **no direct connection**: the messages (always sealed) pass through a **temporary mailbox on the server**, and each side keeps checking that mailbox. This is the mode designed to be used together with the Tor browser, without revealing your IP to anyone.

> In every mode, the **content stays end-to-end encrypted**. The difference between the modes is only the **path** the packets take, not the security of the content.

---

## 5. What Keeps the Conversation Safe

- **Strong encryption (AES-GCM).** Each message is sealed individually in the browser before it leaves.
- **Optional room password.** If you set a password (4 to 8 characters), it strengthens the key. The server never receives it; the other person must type it to get in.
- **Safety code.** Both sides see a small code. If they match on both screens, no one is in the middle of the conversation. Just ask: "is your code the same as mine?"
- **Version check.** If the two people are on different versions of the app, it warns you instead of letting a broken conversation happen.

---

## 6. What Disappears on Its Own (the "no-trace" part)

- **Auto-erase the text.** What appears on screen disappears after a few seconds (you choose the time, from 1 to 10 seconds, or "never").
- **Duration and maximum lifetime.** You can have the room close on its own after a period of inactivity and/or after a total time, even if both people keep typing.
- **"Panic" button.** Instantly wipes everything from the screen and returns to the start. It's for that "someone just walked up" moment.
- **The room on the server erases itself.** The invite held by the "mail carrier" lives for only a few minutes and then vanishes (on Google, about 60 minutes, but it can be sooner).

> ⚠️ One important bit of honesty: auto-erase clears **both of your screens**. It does **not** erase the link you already sent through a messenger (WhatsApp, etc.), nor does it do anything magic on the other person's device. Delete the link yourself from wherever you sent it.

---

## 7. Why It Works the Same on Any Platform

The `index.html` is **exactly the same** on every platform. The only thing that changes is the "mail carrier":

| Platform | The "vault" where invites sit for a few minutes |
|---|---|
| Google Apps Script | CacheService |
| Vercel | Redis (Upstash) |
| Deno | Deno KV |
| Cloudflare | Durable Objects |

They all do **the same thing** (hold a sealed envelope and deliver it), and they all use the **same commands** underneath. That's why you can switch platforms without changing the page. The server never sees the content on any of them.

---

## 8. Summary in 5 Points

1. **Two people, live text, letter by letter.**
2. **End-to-end encryption:** the server is a mail carrier that cannot open the envelopes.
3. **The key travels hidden in the link (after the `#`) and never reaches the server.**
4. **Three modes:** fast (STUN), private (hide your IP with a relay), and anonymous (Tor).
5. **Everything is temporary:** the text disappears, the room expires, and the Panic button wipes it instantly.

*Wisp: a place to talk like someone speaking softly — and the whisper fades into the air.*
