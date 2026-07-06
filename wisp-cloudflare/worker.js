/**
 * Wisp RPC backend for Cloudflare Workers + Durable Objects.
 * Supports WebRTC signaling and Tor Mode encrypted mailbox relay.
 */

const WISP_APP = 'wisp-cloudflare-do-signal';
const WISP_VERSION = 1;
const ROOM_TTL_SECONDS = 3600;
const ROOM_TTL_MS = ROOM_TTL_SECONDS * 1000;
const MAX_PAYLOAD_CHARS = 95000;
const TOR_MAX_MESSAGES = 10;
const TOR_MAX_BLOB_CHARS = 8000;
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/__wisp_rpc') {
      return handleRpcAtEdge(request, env);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return json({ ok: false, error: 'method not allowed.' }, 405);
    }

    const response = await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  }
};

async function handleRpcAtEdge(request, env) {
  if (request.method !== 'POST') return json({ ok: false, error: 'method not allowed.' }, 405);

  let body;
  try { body = await request.json(); } catch (_) { return json({ ok: false, error: 'invalid JSON request.' }, 400); }

  const method = String(body?.method || '');
  const args = Array.isArray(body?.args) ? body.args : [];

  if (!RPC_METHODS.has(method)) return json({ ok: false, error: 'blocked server method.' }, 400);

  if (method === 'gasHealth') {
    return json({ ok: true, service: WISP_APP, version: WISP_VERSION, ttl: ROOM_TTL_SECONDS });
  }

  let room;
  try { room = normalizeRoom(args[0]); } catch (err) { return json({ ok: false, error: errorText(err) }); }

  const id = env.WISP_ROOMS.idFromName(room);
  const stub = env.WISP_ROOMS.get(id);
  return stub.fetch('https://wisp-room.local/rpc', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method, args })
  });
}

export class WispRoom {
  constructor(state, env) {
    this.state = state;
    this.storage = state.storage;
    this.env = env;
  }

  async fetch(request) {
    if (request.method !== 'POST') return json({ ok: false, error: 'method not allowed.' }, 405);

    let body;
    try { body = await request.json(); } catch (_) { return json({ ok: false, error: 'invalid JSON request.' }, 400); }

    const method = String(body?.method || '');
    const args = Array.isArray(body?.args) ? body.args : [];

    if (!RPC_METHODS.has(method) || method === 'gasHealth') return json({ ok: false, error: 'blocked server method.' }, 400);

    try {
      await this.cleanupIfExpired();
      const result = await this.handlers()[method](...args);
      return json(result);
    } catch (err) {
      return json({ ok: false, error: errorText(err) });
    }
  }

  async alarm() {
    await this.cleanupIfExpired(true);
  }

  handlers() {
    return {
      gasCreateRoom: async (room, token, encryptedOffer) => {
        room = normalizeRoom(room);
        validateToken(token);
        validateBlob(encryptedOffer, 'offer');

        if (await this.storage.get('meta')) throw new Error('room already exists. create a new room.');
        if (await this.storage.get('used')) throw new Error('room already used.');

        const meta = { app: WISP_APP, version: WISP_VERSION, createdAt: Date.now(), expiresAt: Date.now() + ROOM_TTL_MS, tokenHash: await tokenHash(token) };
        await this.storage.put('meta', meta);
        await this.storage.put('offer', encryptedOffer);
        await this.scheduleCleanup(meta.expiresAt);
        return { ok: true, ttl: ROOM_TTL_SECONDS };
      },

      gasGetOffer: async (room, token) => {
        room = normalizeRoom(room);
        validateToken(token);

        if (await this.storage.get('used')) return { ok: false, used: true, error: 'room already used.' };
        await this.validateAccess(token);
        if (await this.storage.get('answer')) return { ok: false, used: true, error: 'room already used.' };

        const offer = await this.storage.get('offer');
        if (!offer) return { ok: false, missing: true, error: 'room expired or offer not found.' };
        return { ok: true, offer, ttl: ROOM_TTL_SECONDS };
      },

      gasSetAnswer: async (room, token, encryptedAnswer) => {
        room = normalizeRoom(room);
        validateToken(token);
        validateBlob(encryptedAnswer, 'answer');
        await this.validateAccess(token);

        if (await this.storage.get('used')) throw new Error('room already used.');
        if (await this.storage.get('answer')) throw new Error('room already used.');

        await this.storage.put('answer', encryptedAnswer);
        await this.storage.delete('offer');
        return { ok: true, ttl: ROOM_TTL_SECONDS };
      },

      gasGetAnswer: async (room, token) => {
        room = normalizeRoom(room);
        validateToken(token);
        await this.validateAccess(token);

        const answer = await this.storage.get('answer');
        return { ok: true, answer: answer || null };
      },

      gasDeleteRoom: async (room, token) => {
        room = normalizeRoom(room);
        validateToken(token);

        if (await this.storage.get('meta')) await this.validateAccess(token);
        await this.markUsedAndDelete(['meta', 'offer', 'answer']);
        return { ok: true };
      },

      gasTorCreateRoom: async (room, token) => {
        room = normalizeRoom(room);
        validateToken(token);

        if (await this.storage.get('used')) throw new Error('room already used.');
        if (await this.storage.get('meta')) throw new Error('room already exists. create a new room.');

        const meta = { app: WISP_APP, version: WISP_VERSION, mode: 'tor', createdAt: Date.now(), expiresAt: Date.now() + ROOM_TTL_MS, tokenHash: await tokenHash(token) };
        await this.storage.put('meta', meta);
        await this.storage.put('a2b', []);
        await this.storage.put('b2a', []);
        await this.scheduleCleanup(meta.expiresAt);
        return { ok: true, ttl: ROOM_TTL_SECONDS };
      },

      gasTorJoinRoom: async (room, token) => {
        room = normalizeRoom(room);
        validateToken(token);

        if (await this.storage.get('used')) return { ok: false, used: true, error: 'room already used.' };
        if (await this.storage.get('joined')) return { ok: false, used: true, error: 'room already used.' };

        await this.validateAccess(token);
        await this.storage.put('joined', '1');
        await this.refreshTorRoomTtl();
        return { ok: true, ttl: ROOM_TTL_SECONDS };
      },

      gasTorSend: async (room, token, box, encryptedBlob) => {
        room = normalizeRoom(room);
        validateToken(token);
        validateTorBox(box);
        validateTorBlob(encryptedBlob);
        await this.validateAccess(token);

        let list = await this.storage.get(box);
        if (!Array.isArray(list)) list = [];

        const seq = list.length ? Number(list[list.length - 1].seq || 0) + 1 : 1;
        list.push({ seq, blob: encryptedBlob });
        if (list.length > TOR_MAX_MESSAGES) list = list.slice(list.length - TOR_MAX_MESSAGES);

        await this.storage.put(box, list);
        await this.refreshTorRoomTtl();
        return { ok: true, seq };
      },

      gasTorPoll: async (room, token, box, afterSeq) => {
        room = normalizeRoom(room);
        validateToken(token);
        validateTorBox(box);
        await this.validateAccess(token);

        const after = normalizeSeq(afterSeq);
        let list = await this.storage.get(box);
        if (!Array.isArray(list)) list = [];
        const messages = list.filter(item => item && Number(item.seq || 0) > after);
        return { ok: true, messages, ttl: ROOM_TTL_SECONDS };
      },

      gasTorDeleteRoom: async (room, token) => {
        room = normalizeRoom(room);
        validateToken(token);

        if (await this.storage.get('meta')) await this.validateAccess(token);
        await this.markUsedAndDelete(['meta', 'a2b', 'b2a', 'joined']);
        return { ok: true };
      }
    };
  }

  async validateAccess(token) {
    const meta = await this.storage.get('meta');
    if (!meta) throw new Error('room expired or not found.');
    if (!meta || meta.version !== WISP_VERSION || typeof meta.tokenHash !== 'string') throw new Error('room version is invalid.');
    if (meta.tokenHash !== await tokenHash(token)) throw new Error('wrong room token.');
  }

  async refreshTorRoomTtl() {
    const meta = await this.storage.get('meta');
    if (meta) {
      meta.expiresAt = Date.now() + ROOM_TTL_MS;
      await this.storage.put('meta', meta);
      await this.scheduleCleanup(meta.expiresAt);
    }
  }

  async cleanupIfExpired(force = false) {
    const meta = await this.storage.get('meta');
    if (force || (meta && typeof meta.expiresAt === 'number' && Date.now() > meta.expiresAt)) {
      await this.deleteMany(['meta', 'offer', 'answer', 'a2b', 'b2a', 'joined', 'used']);
      await this.storage.deleteAlarm();
      return true;
    }
    return false;
  }

  async markUsedAndDelete(keys) {
    await this.storage.put('used', '1');
    await this.deleteMany(keys);
    await this.scheduleCleanup(Date.now() + ROOM_TTL_MS);
  }

  async scheduleCleanup(timeMs) {
    await this.storage.setAlarm(timeMs + 60_000);
  }
  async deleteMany(keys) {
    for (const key of keys) {
      await this.storage.delete(key);
    }
  }
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

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
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

function errorText(err) {
  return err && err.message ? err.message : String(err || 'server error.');
}
