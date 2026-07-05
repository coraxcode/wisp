/**
 * Wisp Signal - Deno Deploy + Deno KV
 *
 * Files in this folder:
 *   index.html -> the Wisp browser app
 *   main.ts    -> Deno HTTP server + Deno KV signaling server
 *   deno.json  -> run/deploy helper tasks
 *
 * The browser calls POST /__wisp_rpc when it is not running inside Google Apps Script.
 */

const WISP_APP = 'wisp-deno-kv-signal';
const WISP_VERSION = 1;
const ROOM_TTL_SECONDS = 600;
const ROOM_TTL_MS = ROOM_TTL_SECONDS * 1000;
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

const indexHtml = await Deno.readTextFile(new URL('./index.html', import.meta.url));
const kv = await Deno.openKv();

Deno.serve(async request => {
  const url = new URL(request.url);

  if (url.pathname === '/__wisp_rpc') {
    return handleRpc(request);
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return json({ ok: false, error: 'method not allowed.' }, 405);
  }

  return html(indexHtml);
});

async function handleRpc(request) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'method not allowed.' }, 405);
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
    const offerKey = key(room, 'offer');
    const usedKey = key(room, 'used');

    await cleanupIfExpired(room);

    const used = await kv.get(usedKey);
    if (used.value) throw new Error('room already exists. create a new room.');

    const meta = {
      app: WISP_APP,
      version: WISP_VERSION,
      createdAt: Date.now(),
      expiresAt: Date.now() + ROOM_TTL_MS,
      tokenHash: await tokenHash(token)
    };

    const tx = await kv.atomic()
      .check({ key: metaKey, versionstamp: null })
      .check({ key: usedKey, versionstamp: null })
      .set(metaKey, meta, { expireIn: ROOM_TTL_MS })
      .set(offerKey, encryptedOffer, { expireIn: ROOM_TTL_MS })
      .commit();

    if (!tx.ok) throw new Error('room already exists. create a new room.');
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasGetOffer(room, token) {
    room = normalizeRoom(room);
    validateToken(token);
    await cleanupIfExpired(room);

    if ((await kv.get(key(room, 'used'))).value) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    await validateAccess(room, token);

    if ((await kv.get(key(room, 'answer'))).value) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    const offer = (await kv.get(key(room, 'offer'))).value;
    if (!offer) {
      return { ok: false, missing: true, error: 'room expired or offer not found.' };
    }

    return { ok: true, offer, ttl: ROOM_TTL_SECONDS };
  },

  async gasSetAnswer(room, token, encryptedAnswer) {
    room = normalizeRoom(room);
    validateToken(token);
    validateBlob(encryptedAnswer, 'answer');
    await cleanupIfExpired(room);
    await validateAccess(room, token);

    const answerKey = key(room, 'answer');
    const usedKey = key(room, 'used');
    const answerEntry = await kv.get(answerKey);
    const usedEntry = await kv.get(usedKey);

    if (usedEntry.value) throw new Error('room already used.');
    if (answerEntry.value) throw new Error('room already used.');

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
    await cleanupIfExpired(room);
    await validateAccess(room, token);

    const answer = (await kv.get(key(room, 'answer'))).value;
    return { ok: true, answer: answer || null };
  },

  async gasDeleteRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);
    await cleanupIfExpired(room);

    const meta = (await kv.get(key(room, 'meta'))).value;
    if (meta) await validateAccess(room, token);

    await kv.atomic()
      .set(key(room, 'used'), '1', { expireIn: ROOM_TTL_MS })
      .delete(key(room, 'meta'))
      .delete(key(room, 'offer'))
      .delete(key(room, 'answer'))
      .commit();

    return { ok: true };
  }
};

async function cleanupIfExpired(room) {
  const meta = (await kv.get(key(room, 'meta'))).value;
  if (meta && typeof meta.expiresAt === 'number' && Date.now() > meta.expiresAt) {
    await kv.atomic()
      .delete(key(room, 'meta'))
      .delete(key(room, 'offer'))
      .delete(key(room, 'answer'))
      .delete(key(room, 'used'))
      .commit();
    return true;
  }
  return false;
}

async function validateAccess(room, token) {
  const meta = (await kv.get(key(room, 'meta'))).value;
  if (!meta) throw new Error('room expired or not found.');

  if (!meta || meta.app !== WISP_APP || meta.version !== WISP_VERSION) {
    throw new Error('room version is invalid.');
  }

  if (meta.tokenHash !== await tokenHash(token)) {
    throw new Error('wrong room token.');
  }
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
  if (typeof blob !== 'string') throw new Error('invalid ' + label + '.');
  if (blob.length < 32 || blob.length > MAX_PAYLOAD_CHARS) throw new Error(label + ' size is invalid.');
  if (!BLOB_RE.test(blob)) throw new Error(label + ' format is invalid.');
}

async function tokenHash(token) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
  return base64UrlEncode(digest);
}

function base64UrlEncode(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function key(room, part) {
  return ['wisp', room, part];
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

function html(text) {
  return new Response(text, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  });
}

function errorText(err) {
  return err && err.message ? err.message : String(err || 'server error');
}
