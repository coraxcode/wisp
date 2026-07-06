/**
 * Wisp RPC backend for Deno Deploy + Deno KV.
 * Supports WebRTC signaling and Tor Mode encrypted mailbox relay.
 */

const WISP_APP = 'wisp-deno-kv-signal';
const WISP_VERSION = 1;
const ROOM_TTL_SECONDS = 3600;
const ROOM_TTL_MS = ROOM_TTL_SECONDS * 1000;
const MAX_PAYLOAD_CHARS = 95000;
const TOR_MAX_MESSAGES = 10;
const TOR_MAX_BLOB_CHARS = 5000;
const ROOM_RE = /^[A-Z2-9]{8}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{16,64}$/;
const BLOB_RE = /^g1\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}$/;
const TOR_BOXES = new Set(['a2b', 'b2a']);
const RPC_METHODS = new Set([
  'gasCreateRoom',
  'gasGetOffer',
  'gasSetAnswer',
  'gasGetAnswer',
  'gasDeleteRoom',
  'gasHealth',
  'gasTorCreateRoom',
  'gasTorJoinRoom',
  'gasTorSend',
  'gasTorPoll',
  'gasTorDeleteRoom'
]);

const indexHtml = await Deno.readTextFile(new URL('./index.html', import.meta.url));
const kv = await Deno.openKv();

Deno.serve(async request => {
  const url = new URL(request.url);

  if (url.pathname === '/__wisp_rpc') return handleRpc(request);

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return json({ ok: false, error: 'method not allowed.' }, 405);
  }

  return html(indexHtml);
});

async function handleRpc(request) {
  if (request.method !== 'POST') return json({ ok: false, error: 'method not allowed.' }, 405);

  let body;
  try { body = await request.json(); } catch (_) { return json({ ok: false, error: 'invalid JSON request.' }, 400); }

  const method = String(body?.method || '');
  const args = Array.isArray(body?.args) ? body.args : [];

  if (!RPC_METHODS.has(method)) return json({ ok: false, error: 'blocked server method.' }, 400);

  try {
    if (method === 'gasHealth') {
      return json({ ok: true, service: WISP_APP, version: WISP_VERSION, ttl: ROOM_TTL_SECONDS });
    }
    const result = await handlers[method](...args);
    return json(result);
  } catch (err) {
    return json({ ok: false, error: errorText(err) });
  }
}

const handlers = {
  async gasCreateRoom(room, token, encryptedOffer) {
    room = normalizeRoom(room);
    validateToken(token);
    validateBlob(encryptedOffer, 'offer');

    const metaKey = key(room, 'meta');
    const usedKey = key(room, 'used');
    const meta = { app: WISP_APP, version: WISP_VERSION, createdAt: Date.now(), tokenHash: await tokenHash(token) };

    const tx = await kv.atomic()
      .check({ key: metaKey, versionstamp: null })
      .check({ key: usedKey, versionstamp: null })
      .set(metaKey, meta, { expireIn: ROOM_TTL_MS })
      .set(key(room, 'offer'), encryptedOffer, { expireIn: ROOM_TTL_MS })
      .commit();

    if (!tx.ok) throw new Error('room already exists. create a new room.');
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasGetOffer(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    if ((await kv.get(key(room, 'used'))).value) return { ok: false, used: true, error: 'room already used.' };
    await validateAccess(room, token);
    if ((await kv.get(key(room, 'answer'))).value) return { ok: false, used: true, error: 'room already used.' };

    const offer = (await kv.get(key(room, 'offer'))).value;
    if (!offer) return { ok: false, missing: true, error: 'room expired or offer not found.' };
    return { ok: true, offer, ttl: ROOM_TTL_SECONDS };
  },

  async gasSetAnswer(room, token, encryptedAnswer) {
    room = normalizeRoom(room);
    validateToken(token);
    validateBlob(encryptedAnswer, 'answer');
    await validateAccess(room, token);

    const answerKey = key(room, 'answer');
    const usedKey = key(room, 'used');
    const tx = await kv.atomic()
      .check({ key: answerKey, versionstamp: null })
      .check({ key: usedKey, versionstamp: null })
      .set(answerKey, encryptedAnswer, { expireIn: ROOM_TTL_MS })
      .delete(key(room, 'offer'))
      .commit();

    if (!tx.ok) throw new Error('room already used.');
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasGetAnswer(room, token) {
    room = normalizeRoom(room);
    validateToken(token);
    await validateAccess(room, token);

    const answer = (await kv.get(key(room, 'answer'))).value;
    return { ok: true, answer: answer || null };
  },

  async gasDeleteRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    const meta = (await kv.get(key(room, 'meta'))).value;
    if (meta) await validateAccess(room, token);

    await kv.atomic()
      .set(key(room, 'used'), '1', { expireIn: ROOM_TTL_MS })
      .delete(key(room, 'meta'))
      .delete(key(room, 'offer'))
      .delete(key(room, 'answer'))
      .commit();

    return { ok: true };
  },

  async gasTorCreateRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    const metaKey = key(room, 'meta');
    const usedKey = key(room, 'used');
    const meta = { app: WISP_APP, version: WISP_VERSION, mode: 'tor', createdAt: Date.now(), tokenHash: await tokenHash(token) };

    const tx = await kv.atomic()
      .check({ key: metaKey, versionstamp: null })
      .check({ key: usedKey, versionstamp: null })
      .set(metaKey, meta, { expireIn: ROOM_TTL_MS })
      .set(key(room, 'a2b'), [], { expireIn: ROOM_TTL_MS })
      .set(key(room, 'b2a'), [], { expireIn: ROOM_TTL_MS })
      .commit();

    if (!tx.ok) throw new Error('room already exists. create a new room.');
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasTorJoinRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    if ((await kv.get(key(room, 'used'))).value) return { ok: false, used: true, error: 'room already used.' };
    await validateAccess(room, token);

    const joinedKey = key(room, 'joined');
    const tx = await kv.atomic()
      .check({ key: joinedKey, versionstamp: null })
      .set(joinedKey, '1', { expireIn: ROOM_TTL_MS })
      .commit();

    if (!tx.ok) return { ok: false, used: true, error: 'room already used.' };
    await refreshTorRoomTtl(room);
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasTorSend(room, token, box, encryptedBlob) {
    room = normalizeRoom(room);
    validateToken(token);
    validateTorBox(box);
    validateTorBlob(encryptedBlob);
    await validateAccess(room, token);

    const boxKey = key(room, box);
    const current = await kv.get(boxKey);
    let list = Array.isArray(current.value) ? current.value : [];
    const seq = list.length ? Number(list[list.length - 1].seq || 0) + 1 : 1;
    list = [...list, { seq, blob: encryptedBlob }];
    if (list.length > TOR_MAX_MESSAGES) list = list.slice(list.length - TOR_MAX_MESSAGES);

    await kv.set(boxKey, list, { expireIn: ROOM_TTL_MS });
    await refreshTorRoomTtl(room);
    return { ok: true, seq };
  },

  async gasTorPoll(room, token, box, afterSeq) {
    room = normalizeRoom(room);
    validateToken(token);
    validateTorBox(box);
    await validateAccess(room, token);

    const after = normalizeSeq(afterSeq);
    const value = (await kv.get(key(room, box))).value;
    const list = Array.isArray(value) ? value : [];
    const messages = list.filter(item => item && Number(item.seq || 0) > after);
    return { ok: true, messages, ttl: ROOM_TTL_SECONDS };
  },

  async gasTorDeleteRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    const meta = (await kv.get(key(room, 'meta'))).value;
    if (meta) await validateAccess(room, token);

    await kv.atomic()
      .set(key(room, 'used'), '1', { expireIn: ROOM_TTL_MS })
      .delete(key(room, 'meta'))
      .delete(key(room, 'a2b'))
      .delete(key(room, 'b2a'))
      .delete(key(room, 'joined'))
      .commit();

    return { ok: true };
  }
};

async function refreshTorRoomTtl(room) {
  const meta = (await kv.get(key(room, 'meta'))).value;
  if (meta) await kv.set(key(room, 'meta'), meta, { expireIn: ROOM_TTL_MS });

  const joined = (await kv.get(key(room, 'joined'))).value;
  if (joined) await kv.set(key(room, 'joined'), joined, { expireIn: ROOM_TTL_MS });

  for (const box of ['a2b', 'b2a']) {
    const value = (await kv.get(key(room, box))).value;
    if (Array.isArray(value)) await kv.set(key(room, box), value, { expireIn: ROOM_TTL_MS });
  }
}

async function validateAccess(room, token) {
  const meta = (await kv.get(key(room, 'meta'))).value;
  if (!meta) throw new Error('room expired or not found.');
  if (!meta || meta.version !== WISP_VERSION || typeof meta.tokenHash !== 'string') throw new Error('room version is invalid.');
  if (meta.tokenHash !== await tokenHash(token)) throw new Error('wrong room token.');
}

function html(text) {
  return new Response(text, { headers: securityHeaders({ 'Content-Type': 'text/html; charset=utf-8' }) });
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: securityHeaders({ 'Content-Type': 'application/json; charset=utf-8' }) });
}

function securityHeaders(extra = {}) {
  return {
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    ...extra
  };
}

function normalizeRoom(room) {
  room = String(room || '').trim().toUpperCase();
  validateRoom(room);
  return room;
}

function validateRoom(room) {
  if (typeof room !== 'string' || !ROOM_RE.test(room)) throw new Error('invalid room id.');
}

function validateToken(token) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) throw new Error('invalid room token.');
}

function validateBlob(blob, label) {
  if (typeof blob !== 'string') throw new Error(`invalid ${label}.`);
  if (blob.length < 32 || blob.length > MAX_PAYLOAD_CHARS) throw new Error(`${label} size is invalid.`);
  if (!BLOB_RE.test(blob)) throw new Error(`${label} format is invalid.`);
}

function validateTorBlob(blob) {
  if (typeof blob !== 'string') throw new Error('invalid message.');
  if (blob.length < 16 || blob.length > TOR_MAX_BLOB_CHARS) throw new Error('message size is invalid.');
  if (!BLOB_RE.test(blob)) throw new Error('message format is invalid.');
}

function validateTorBox(box) {
  if (!TOR_BOXES.has(box)) throw new Error('invalid mailbox.');
}

function normalizeSeq(value) {
  const n = Number.parseInt(String(value), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

async function tokenHash(token) {
  const bytes = new TextEncoder().encode(String(token));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function key(room, part) {
  return ['wisp', room, part];
}

function errorText(err) {
  return err && err.message ? err.message : String(err || 'server error.');
}
