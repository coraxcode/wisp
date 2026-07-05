/**
 * Wisp Signal - Cloudflare Worker + Durable Object
 *
 * Files in this folder:
 *   public/index.html  -> the Wisp browser app
 *   worker.js          -> Cloudflare Worker + Durable Object signaling server
 *   wrangler.toml      -> Durable Object and static asset bindings
 *
 * The browser calls POST /__wisp_rpc when it is not running inside Google Apps Script.
 * This Worker implements the same RPC method names as Code.gs so index.html can stay universal.
 */

const WISP_APP = 'wisp-cloudflare-durable-signal';
const WISP_VERSION = 1;
const ROOM_TTL_SECONDS = 600;
const MAX_PAYLOAD_CHARS = 95000;
const ROOM_RE = /^[A-Z2-9]{8}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{16,64}$/;
const BLOB_RE = /^g1\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}$/;
const RPC_METHODS = new Set([
  'gasCreateRoom',
  'gasGetOffer',
  'gasSetAnswer',
  'gasGetAnswer',
  'gasDeleteRoom',
  'gasHealth'
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/__wisp_rpc') {
      return handleRpc(request, env);
    }

    // Serve index.html and other static assets through the Assets binding.
    if (env.ASSETS) {
      const response = await env.ASSETS.fetch(request);
      return withNoStore(response);
    }

    return json({ ok: false, error: 'static asset binding ASSETS is not configured.' }, 500);
  }
};

async function handleRpc(request, env) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method not allowed.' }, 405);
  }

  if (!env.WISP_ROOMS) {
    return json({ ok: false, error: 'Durable Object binding WISP_ROOMS is not configured.' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return json({ ok: false, error: 'invalid JSON request.' }, 400);
  }

  const method = String(body && body.method || '');
  const args = Array.isArray(body && body.args) ? body.args : [];

  if (!RPC_METHODS.has(method)) {
    return json({ ok: false, error: 'blocked server method.' }, 400);
  }

  if (method === 'gasHealth') {
    return json({ ok: true, service: WISP_APP, version: WISP_VERSION, ttl: ROOM_TTL_SECONDS });
  }

  const room = String(args[0] || '').trim().toUpperCase();
  try {
    validateRoom(room);
  } catch (err) {
    return json({ ok: false, error: errorText(err) }, 400);
  }

  try {
    // One Durable Object per room gives each room serialized, race-free state.
    const id = env.WISP_ROOMS.idFromName(room);
    const stub = env.WISP_ROOMS.get(id);
    const response = await stub.fetch('https://wisp-room.internal/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method, args })
    });
    return withNoStore(response);
  } catch (err) {
    return json({ ok: false, error: errorText(err) }, 500);
  }
}

export class WispRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    if (request.method !== 'POST') {
      return json({ ok: false, error: 'method not allowed.' }, 405);
    }

    try {
      const body = await request.json();
      const method = String(body && body.method || '');
      const args = Array.isArray(body && body.args) ? body.args : [];

      if (!RPC_METHODS.has(method) || method === 'gasHealth') {
        throw new Error('blocked server method.');
      }

      if (typeof this[method] !== 'function') {
        throw new Error('server method not found.');
      }

      const result = await this[method](...args);
      return json(result);
    } catch (err) {
      return json({ ok: false, error: errorText(err) });
    }
  }

  async alarm() {
    await this.state.storage.deleteAll();
  }

  async cleanupIfExpired() {
    const expiresAt = await this.state.storage.get('expiresAt');
    if (typeof expiresAt === 'number' && Date.now() > expiresAt) {
      await this.state.storage.deleteAll();
      return true;
    }
    return false;
  }

  async refreshAlarm() {
    const expiresAt = Date.now() + ROOM_TTL_SECONDS * 1000;
    await this.state.storage.put('expiresAt', expiresAt);
    await this.state.storage.setAlarm(expiresAt + 1000);
    return expiresAt;
  }

  async gasCreateRoom(room, token, encryptedOffer) {
    validateRoom(room);
    validateToken(token);
    validateBlob(encryptedOffer, 'offer');

    await this.cleanupIfExpired();

    const meta = await this.state.storage.get('meta');
    const used = await this.state.storage.get('used');
    if (meta || used) {
      throw new Error('room already exists. create a new room.');
    }

    const expiresAt = await this.refreshAlarm();
    await this.state.storage.put('meta', {
      app: WISP_APP,
      version: WISP_VERSION,
      createdAt: Date.now(),
      expiresAt,
      tokenHash: await tokenHash(token)
    });
    await this.state.storage.put('offer', encryptedOffer);

    return { ok: true, ttl: ROOM_TTL_SECONDS };
  }

  async gasGetOffer(room, token) {
    validateRoom(room);
    validateToken(token);

    await this.cleanupIfExpired();

    if (await this.state.storage.get('used')) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    await this.validateAccess(room, token);

    if (await this.state.storage.get('answer')) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    const offer = await this.state.storage.get('offer');
    if (!offer) {
      return { ok: false, missing: true, error: 'room expired or offer not found.' };
    }

    return { ok: true, offer, ttl: ROOM_TTL_SECONDS };
  }

  async gasSetAnswer(room, token, encryptedAnswer) {
    validateRoom(room);
    validateToken(token);
    validateBlob(encryptedAnswer, 'answer');

    await this.cleanupIfExpired();
    await this.validateAccess(room, token);

    if (await this.state.storage.get('used')) {
      throw new Error('room already used.');
    }

    if (await this.state.storage.get('answer')) {
      throw new Error('room already used.');
    }

    await this.refreshAlarm();
    await this.state.storage.put('answer', encryptedAnswer);
    await this.state.storage.delete('offer');

    return { ok: true, ttl: ROOM_TTL_SECONDS };
  }

  async gasGetAnswer(room, token) {
    validateRoom(room);
    validateToken(token);

    await this.cleanupIfExpired();
    await this.validateAccess(room, token);

    const answer = await this.state.storage.get('answer');
    return { ok: true, answer: answer || null };
  }

  async gasDeleteRoom(room, token) {
    validateRoom(room);
    validateToken(token);

    await this.cleanupIfExpired();

    const meta = await this.state.storage.get('meta');
    if (meta) {
      await this.validateAccess(room, token);
    }

    await this.refreshAlarm();
    await this.state.storage.put('used', '1');
    await this.state.storage.delete('meta');
    await this.state.storage.delete('offer');
    await this.state.storage.delete('answer');

    return { ok: true };
  }

  async validateAccess(room, token) {
    const meta = await this.state.storage.get('meta');
    if (!meta) {
      throw new Error('room expired or not found.');
    }

    if (!meta || meta.app !== WISP_APP || meta.version !== WISP_VERSION) {
      throw new Error('room version is invalid.');
    }

    if (meta.tokenHash !== await tokenHash(token)) {
      throw new Error('wrong room token.');
    }
  }
}

function validateRoom(room) {
  if (typeof room !== 'string' || !ROOM_RE.test(room)) {
    throw new Error('invalid room id.');
  }
}

function validateToken(token) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
    throw new Error('invalid room token.');
  }
}

function validateBlob(blob, label) {
  if (typeof blob !== 'string') {
    throw new Error('invalid ' + label + '.');
  }
  if (blob.length < 32 || blob.length > MAX_PAYLOAD_CHARS) {
    throw new Error(label + ' size is invalid.');
  }
  if (!BLOB_RE.test(blob)) {
    throw new Error(label + ' format is invalid.');
  }
}

async function tokenHash(token) {
  const bytes = new TextEncoder().encode(token);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return base64UrlEncode(digest);
}

function base64UrlEncode(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

function withNoStore(response) {
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  headers.set('Pragma', 'no-cache');
  headers.set('Expires', '0');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function errorText(err) {
  return err && err.message ? err.message : String(err || 'server error');
}
