/*
 * Wisp RPC backend for Vercel + Upstash Redis REST.
 * Supports WebRTC signaling and Tor Mode encrypted mailbox relay.
 *
 * Required environment variables:
 *   UPSTASH_REDIS_REST_URL
 *   UPSTASH_REDIS_REST_TOKEN
 */
'use strict';

const { createHash } = require('node:crypto');

const WISP_APP = 'wisp-vercel-upstash-signal';
const WISP_VERSION = 1;
const ROOM_TTL_SECONDS = 3600;
const MAX_PAYLOAD_CHARS = 95000;
const TOR_MAX_MESSAGES = 20;
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

function setSecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

module.exports = async function handler(req, res) {
  setSecurityHeaders(res);

  if (req.method !== 'POST') {
    return send(res, 405, { ok: false, error: 'method not allowed.' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (_) { return send(res, 400, { ok: false, error: 'invalid JSON request.' }); }
  }
  if (!body || typeof body !== 'object') {
    return send(res, 400, { ok: false, error: 'invalid JSON request.' });
  }

  const method = String(body.method || '');
  const args = Array.isArray(body.args) ? body.args : [];

  if (!RPC_METHODS.has(method)) {
    return send(res, 400, { ok: false, error: 'blocked server method.' });
  }

  try {
    if (method === 'gasHealth') {
      return send(res, 200, { ok: true, service: WISP_APP, version: WISP_VERSION, ttl: ROOM_TTL_SECONDS });
    }
    requireRedisEnv();
    const result = await handlers[method](...args);
    return send(res, 200, result);
  } catch (err) {
    return send(res, 200, { ok: false, error: errorText(err) });
  }
};

function send(res, status, payload) {
  res.status(status).json(payload);
}

const handlers = {
  async gasCreateRoom(room, token, encryptedOffer) {
    room = normalizeRoom(room);
    validateToken(token);
    validateBlob(encryptedOffer, 'offer');

    if (await redis(['GET', key(room, 'used')])) throw new Error('room already used.');

    const meta = {
      app: WISP_APP,
      version: WISP_VERSION,
      createdAt: Date.now(),
      tokenHash: tokenHash(token)
    };

    const metaSet = await redis(['SET', key(room, 'meta'), JSON.stringify(meta), 'EX', ROOM_TTL_SECONDS, 'NX']);
    if (metaSet !== 'OK') throw new Error('room already exists. create a new room.');

    await redis(['SET', key(room, 'offer'), encryptedOffer, 'EX', ROOM_TTL_SECONDS]);
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasGetOffer(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    if (await redis(['GET', key(room, 'used')])) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    await validateAccess(room, token);

    if (await redis(['GET', key(room, 'answer')])) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    const offer = await redis(['GET', key(room, 'offer')]);
    if (!offer) return { ok: false, missing: true, error: 'room expired or offer not found.' };

    return { ok: true, offer, ttl: ROOM_TTL_SECONDS };
  },

  async gasSetAnswer(room, token, encryptedAnswer) {
    room = normalizeRoom(room);
    validateToken(token);
    validateBlob(encryptedAnswer, 'answer');
    await validateAccess(room, token);

    if (await redis(['GET', key(room, 'used')])) throw new Error('room already used.');

    const answerSet = await redis(['SET', key(room, 'answer'), encryptedAnswer, 'EX', ROOM_TTL_SECONDS, 'NX']);
    if (answerSet !== 'OK') throw new Error('room already used.');

    await redis(['DEL', key(room, 'offer')]);
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasGetAnswer(room, token) {
    room = normalizeRoom(room);
    validateToken(token);
    await validateAccess(room, token);

    const answer = await redis(['GET', key(room, 'answer')]);
    return { ok: true, answer: answer || null };
  },

  async gasDeleteRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    const meta = await redis(['GET', key(room, 'meta')]);
    if (meta) await validateAccess(room, token);

    await redis(['SET', key(room, 'used'), '1', 'EX', ROOM_TTL_SECONDS]);
    await redis(['DEL', key(room, 'meta'), key(room, 'offer'), key(room, 'answer')]);
    return { ok: true };
  },

  async gasTorCreateRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    if (await redis(['GET', key(room, 'used')])) throw new Error('room already used.');

    const meta = {
      app: WISP_APP,
      version: WISP_VERSION,
      mode: 'tor',
      createdAt: Date.now(),
      tokenHash: tokenHash(token)
    };

    const metaSet = await redis(['SET', key(room, 'meta'), JSON.stringify(meta), 'EX', ROOM_TTL_SECONDS, 'NX']);
    if (metaSet !== 'OK') throw new Error('room already exists. create a new room.');

    await redis(['SET', key(room, 'a2b'), '[]', 'EX', ROOM_TTL_SECONDS]);
    await redis(['SET', key(room, 'b2a'), '[]', 'EX', ROOM_TTL_SECONDS]);
    return { ok: true, ttl: ROOM_TTL_SECONDS };
  },

  async gasTorJoinRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    if (await redis(['GET', key(room, 'used')])) return { ok: false, used: true, error: 'room already used.' };
    if (await redis(['GET', key(room, 'joined')])) return { ok: false, used: true, error: 'room already used.' };

    await validateAccess(room, token);
    const joinedSet = await redis(['SET', key(room, 'joined'), '1', 'EX', ROOM_TTL_SECONDS, 'NX']);
    if (joinedSet !== 'OK') return { ok: false, used: true, error: 'room already used.' };

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
    let list = parseList(await redis(['GET', boxKey]));
    const seq = list.length ? Number(list[list.length - 1].seq || 0) + 1 : 1;
    list.push({ seq, blob: encryptedBlob });
    if (list.length > TOR_MAX_MESSAGES) list = list.slice(list.length - TOR_MAX_MESSAGES);

    await redis(['SET', boxKey, JSON.stringify(list), 'EX', ROOM_TTL_SECONDS]);
    await refreshTorRoomTtl(room);
    return { ok: true, seq };
  },

  async gasTorPoll(room, token, box, afterSeq) {
    room = normalizeRoom(room);
    validateToken(token);
    validateTorBox(box);
    await validateAccess(room, token);

    const after = normalizeSeq(afterSeq);
    const list = parseList(await redis(['GET', key(room, box)]));
    const messages = list.filter(item => item && Number(item.seq || 0) > after);
    return { ok: true, messages, ttl: ROOM_TTL_SECONDS };
  },

  async gasTorDeleteRoom(room, token) {
    room = normalizeRoom(room);
    validateToken(token);

    const meta = await redis(['GET', key(room, 'meta')]);
    if (meta) await validateAccess(room, token);

    await redis(['SET', key(room, 'used'), '1', 'EX', ROOM_TTL_SECONDS]);
    await redis(['DEL', key(room, 'meta'), key(room, 'a2b'), key(room, 'b2a'), key(room, 'joined')]);
    return { ok: true };
  }
};

async function refreshTorRoomTtl(room) {
  await Promise.allSettled([
    redis(['EXPIRE', key(room, 'meta'), ROOM_TTL_SECONDS]),
    redis(['EXPIRE', key(room, 'joined'), ROOM_TTL_SECONDS]),
    redis(['EXPIRE', key(room, 'a2b'), ROOM_TTL_SECONDS]),
    redis(['EXPIRE', key(room, 'b2a'), ROOM_TTL_SECONDS])
  ]);
}

async function validateAccess(room, token) {
  const metaText = await redis(['GET', key(room, 'meta')]);
  if (!metaText) throw new Error('room expired or not found.');

  let meta;
  try { meta = JSON.parse(metaText); } catch (_) { throw new Error('room data is corrupted.'); }

  if (!meta || meta.version !== WISP_VERSION || typeof meta.tokenHash !== 'string') {
    throw new Error('room version is invalid.');
  }

  if (meta.tokenHash !== tokenHash(token)) throw new Error('wrong room token.');
}

function requireRedisEnv() {
  if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
    throw new Error('server is missing Upstash Redis environment variables.');
  }
}

async function redis(command) {
  const response = await fetch(process.env.UPSTASH_REDIS_REST_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(command)
  });

  let data;
  try { data = await response.json(); } catch (_) { throw new Error('redis returned an invalid response.'); }
  if (!response.ok || data.error) throw new Error(data.error || 'redis command failed.');
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

function parseList(text) {
  if (!text) return [];
  try {
    const value = JSON.parse(text);
    return Array.isArray(value) ? value : [];
  } catch (_) {
    return [];
  }
}

function tokenHash(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

function key(room, part) {
  return `wisp:${room}:${part}`;
}

function errorText(err) {
  return err && err.message ? err.message : String(err || 'server error.');
}
