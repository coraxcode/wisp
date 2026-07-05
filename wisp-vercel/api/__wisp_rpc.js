/**
 * Wisp Signal - Vercel API Function + Upstash Redis/Vercel KV-compatible REST
 *
 * Files in this folder:
 *   index.html          -> the Wisp browser app, served as a static file
 *   api/__wisp_rpc.js   -> RPC signaling endpoint
 *   vercel.json         -> rewrites /__wisp_rpc to /api/__wisp_rpc
 *
 * Required environment variables:
 *   UPSTASH_REDIS_REST_URL
 *   UPSTASH_REDIS_REST_TOKEN
 */

const crypto = require('node:crypto');

const WISP_APP = 'wisp-vercel-redis-signal';
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

module.exports = async function handler(req, res) {
  noStore(res);

  if (req.method !== 'POST') {
    return send(res, 405, { ok: false, error: 'method not allowed.' });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (_) {
    return send(res, 400, { ok: false, error: 'invalid JSON request.' });
  }

  const method = String(body && body.method || '');
  const args = Array.isArray(body && body.args) ? body.args : [];

  if (!RPC_METHODS.has(method)) {
    return send(res, 400, { ok: false, error: 'blocked server method.' });
  }

  try {
    if (method === 'gasHealth') {
      return send(res, 200, { ok: true, service: WISP_APP, version: WISP_VERSION, ttl: ROOM_TTL_SECONDS });
    }

    const result = await handlers[method](...args);
    return send(res, 200, result);
  } catch (err) {
    return send(res, 200, { ok: false, error: errorText(err) });
  }
};

const handlers = {
  async gasCreateRoom(room, token, encryptedOffer) {
    room = normalizeRoom(room);
    validateToken(token);
    validateBlob(encryptedOffer, 'offer');

    const metaKey = key(room, 'meta');
    const offerKey = key(room, 'offer');
    const usedKey = key(room, 'used');

    if (await redis('GET', usedKey)) {
      throw new Error('room already exists. create a new room.');
    }

    const meta = {
      app: WISP_APP,
      version: WISP_VERSION,
      createdAt: Date.now(),
      tokenHash: tokenHash(token)
    };

    const created = await redis('SET', metaKey, JSON.stringify(meta), 'NX', 'EX', String(ROOM_TTL_SECONDS));
    if (created !== 'OK') {
      throw new Error('room already exists. create a new room.');
    }

    try {
      await redis('SET', offerKey, encryptedOffer, 'EX', String(ROOM_TTL_SECONDS));
    } catch (err) {
      await redis('DEL', metaKey).catch(() => null);
      throw err;
    }

    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasGetOffer(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    if (await redis('GET', key(room, 'used'))) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    await validateAccess(room, token);

    if (await redis('GET', key(room, 'answer'))) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    const offer = await redis('GET', key(room, 'offer'));
    if (!offer) {
      return { ok: false, missing: true, error: 'room expired or offer not found.' };
    }

    return { ok: true, offer, ttl: ROOM_TTL_SECONDS };
  },

  async gasSetAnswer(room, token, encryptedAnswer) {
    room = normalizeRoom(room);
    validateToken(token);
    validateBlob(encryptedAnswer, 'answer');
    await validateAccess(room, token);

    if (await redis('GET', key(room, 'used'))) throw new Error('room already used.');

    const setResult = await redis('SET', key(room, 'answer'), encryptedAnswer, 'NX', 'EX', String(ROOM_TTL_SECONDS));
    if (setResult !== 'OK') throw new Error('room already used.');

    await redis('DEL', key(room, 'offer'));
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasGetAnswer(room, token) {
    room = normalizeRoom(room);
    validateToken(token);
    await validateAccess(room, token);

    const answer = await redis('GET', key(room, 'answer'));
    return { ok: true, answer: answer || null };
  },

  async gasDeleteRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    const meta = await redis('GET', key(room, 'meta'));
    if (meta) await validateAccess(room, token);

    await redis('SET', key(room, 'used'), '1', 'EX', String(ROOM_TTL_SECONDS));
    await redis('DEL', key(room, 'meta'), key(room, 'offer'), key(room, 'answer'));
    return { ok: true };
  }
};

async function validateAccess(room, token) {
  const metaText = await redis('GET', key(room, 'meta'));
  if (!metaText) throw new Error('room expired or not found.');

  let meta;
  try {
    meta = JSON.parse(metaText);
  } catch (_) {
    throw new Error('room data is corrupted.');
  }

  if (!meta || meta.app !== WISP_APP || meta.version !== WISP_VERSION) {
    throw new Error('room version is invalid.');
  }

  if (meta.tokenHash !== tokenHash(token)) {
    throw new Error('wrong room token.');
  }
}

async function redis(command, ...args) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) {
    throw new Error('Redis environment variables are not configured.');
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify([command, ...args])
  });

  let data;
  try {
    data = await response.json();
  } catch (_) {
    throw new Error('invalid Redis response.');
  }

  if (!response.ok || data.error) {
    throw new Error(data.error || 'Redis request failed.');
  }

  return data.result;
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

function tokenHash(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('base64url');
}

function key(room, part) {
  return 'wisp:' + room + ':' + part;
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body || '{}');

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : {};
}

function noStore(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}

function errorText(err) {
  return err && err.message ? err.message : String(err || 'server error');
}
