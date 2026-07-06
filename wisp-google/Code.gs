/**
 * Wisp Signal - Google Apps Script + CacheService
 * ASCII/ES5-compatible Code.gs for maximum Apps Script compatibility.
 *
 * This file stores encrypted WebRTC offer/answer blobs temporarily.
 * It never receives the room secret (#k=...), so it cannot decrypt setup data.
 * In WebRTC mode, chat messages do not pass through Apps Script; they travel over WebRTC DataChannel.
 * In Tor Mode, only end-to-end encrypted message blobs pass through temporary CacheService mailboxes.
 */

var WISP_APP = 'wisp-gas-cache-signal';
var WISP_VERSION = 1;
var ROOM_TTL_SECONDS = 3600; // 60 minutes. CacheService may evict earlier.
var MAX_PAYLOAD_CHARS = 95000; // CacheService key values are limited; keep a safety margin.
var ROOM_RE = /^[A-Z2-9]{8}$/;
var TOKEN_RE = /^[A-Za-z0-9_-]{16,64}$/;
var BLOB_RE = /^g1\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}$/;

function doGet(e) {
  var params = {};
  if (e && e.parameter) {
    params = e.parameter;
  }

  if (params.health === '1') {
    return jsonOutput_({ ok: true, service: WISP_APP, version: WISP_VERSION });
  }

  var template = HtmlService.createTemplateFromFile('index');
  template.webAppUrl = ScriptApp.getService().getUrl();

  var output = template.evaluate();
  output.setTitle('wisp - private live chat');
  // CRITICAL for mobile: Apps Script serves the page inside an iframe and ignores
  // the <meta viewport> that is inside Index.html. The viewport must be set here,
  // on the server output, or phones load the desktop-width wrapper instead.
  output.addMetaTag('viewport', 'width=device-width, initial-scale=1, viewport-fit=cover');
  output.setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT);
  return output;
}

function gasHealth() {
  return { ok: true, service: WISP_APP, version: WISP_VERSION, ttl: ROOM_TTL_SECONDS };
}

function gasCreateRoom(room, token, encryptedOffer) {
  return withLock_(function () {
    validateRoom_(room);
    validateToken_(token);
    validateBlob_(encryptedOffer, 'offer');

    var cache = CacheService.getScriptCache();
    var metaKey = key_(room, 'meta');

    if (cache.get(key_(room, 'used'))) {
      throw new Error('room already used.');
    }

    if (cache.get(metaKey)) {
      throw new Error('room already exists. create a new room.');
    }

    var meta = {
      app: WISP_APP,
      version: WISP_VERSION,
      createdAt: new Date().getTime(),
      tokenHash: tokenHash_(token)
    };

    cache.put(metaKey, JSON.stringify(meta), ROOM_TTL_SECONDS);
    cache.put(key_(room, 'offer'), encryptedOffer, ROOM_TTL_SECONDS);

    return { ok: true, ttl: ROOM_TTL_SECONDS };
  });
}

function gasGetOffer(room, token) {
  validateRoom_(room);
  validateToken_(token);

  var cache = CacheService.getScriptCache();

  // A wisp room connects exactly 2 people. Once used or closed, block everyone else.
  if (cache.get(key_(room, 'used'))) {
    return { ok: false, used: true, error: 'room already used.' };
  }

  validateAccess_(room, token);

  // If an answer already exists, a second person already joined this room.
  if (cache.get(key_(room, 'answer'))) {
    return { ok: false, used: true, error: 'room already used.' };
  }

  var offer = cache.get(key_(room, 'offer'));
  if (!offer) {
    return { ok: false, missing: true, error: 'room expired or offer not found.' };
  }

  return { ok: true, offer: offer, ttl: ROOM_TTL_SECONDS };
}

function gasSetAnswer(room, token, encryptedAnswer) {
  return withLock_(function () {
    validateRoom_(room);
    validateAccess_(room, token);
    validateBlob_(encryptedAnswer, 'answer');

    var cache = CacheService.getScriptCache();

    if (cache.get(key_(room, 'used'))) {
      throw new Error('room already used.');
    }

    var existing = cache.get(key_(room, 'answer'));
    if (existing) {
      throw new Error('room already used.');
    }

    cache.put(key_(room, 'answer'), encryptedAnswer, ROOM_TTL_SECONDS);

    // Step 3 done: the answer is safely stored. The offer is no longer needed by
    // anyone — the creator keeps its own offer in memory and only polls for the
    // answer from here on. Removing it now shrinks the window where any encrypted
    // setup data sits on the server.
    cache.remove(key_(room, 'offer'));

    return { ok: true, ttl: ROOM_TTL_SECONDS };
  });
}

function gasGetAnswer(room, token) {
  validateRoom_(room);
  validateAccess_(room, token);

  var answer = CacheService.getScriptCache().get(key_(room, 'answer'));
  if (!answer) {
    return { ok: true, answer: null };
  }

  return { ok: true, answer: answer };
}

function gasDeleteRoom(room, token) {
  validateRoom_(room);
  validateAccess_(room, token);

  var cache = CacheService.getScriptCache();

  // Leave a small "used" marker so anyone opening this link later sees
  // "room already used" instead of a confusing generic error.
  cache.put(key_(room, 'used'), '1', ROOM_TTL_SECONDS);

  cache.remove(key_(room, 'meta'));
  cache.remove(key_(room, 'offer'));
  cache.remove(key_(room, 'answer'));

  return { ok: true };
}

// ============================================================
// TOR MODE — server-relayed encrypted mailbox (no WebRTC).
// The server only stores encrypted blobs and never reads them.
// Each room has two mailboxes: 'a2b' (creator -> joiner) and 'b2a'.
// ============================================================

var TOR_MAX_MESSAGES = 10;           // live typing does not need long history
var TOR_MAX_BLOB_CHARS = 5000;       // max size of one encrypted chat blob

function gasTorCreateRoom(room, token) {
  return withLock_(function () {
    validateRoom_(room);
    validateToken_(token);

    var cache = CacheService.getScriptCache();
    var metaKey = key_(room, 'meta');

    if (cache.get(key_(room, 'used'))) {
      throw new Error('room already used.');
    }
    if (cache.get(metaKey)) {
      throw new Error('room already exists. create a new room.');
    }

    var meta = {
      app: WISP_APP,
      version: WISP_VERSION,
      mode: 'tor',
      createdAt: Date.now(),
      tokenHash: tokenHash_(token)
    };

    cache.put(metaKey, JSON.stringify(meta), ROOM_TTL_SECONDS);
    cache.put(key_(room, 'a2b'), '[]', ROOM_TTL_SECONDS);
    cache.put(key_(room, 'b2a'), '[]', ROOM_TTL_SECONDS);

    return { ok: true, ttl: ROOM_TTL_SECONDS };
  });
}

function gasTorJoinRoom(room, token) {
  return withLock_(function () {
    validateRoom_(room);
    validateToken_(token);

    var cache = CacheService.getScriptCache();

    // Check "used"/"joined" BEFORE validateAccess_, so a late joiner gets a clean
    // "room already used" instead of a confusing "room not found" after cleanup.
    if (cache.get(key_(room, 'used'))) {
      return { ok: false, used: true, error: 'room already used.' };
    }
    if (cache.get(key_(room, 'joined'))) {
      return { ok: false, used: true, error: 'room already used.' };
    }

    validateAccess_(room, token);

    // Mark that a second person has joined. A third join is refused.
    cache.put(key_(room, 'joined'), '1', ROOM_TTL_SECONDS);

    refreshTorRoomTtl_(room);

    return { ok: true, ttl: ROOM_TTL_SECONDS };
  });
}

function gasTorSend(room, token, box, encryptedBlob) {
  return withLock_(function () {
    validateRoom_(room);
    validateAccess_(room, token);
    validateTorBox_(box);
    validateTorBlob_(encryptedBlob);

    var cache = CacheService.getScriptCache();
    var boxKey = key_(room, box);

    var listText = cache.get(boxKey);
    var list = [];
    if (listText) {
      try { list = JSON.parse(listText); } catch (err) { list = []; }
    }
    if (!Array.isArray(list)) { list = []; }

    var seq = list.length ? (list[list.length - 1].seq + 1) : 1;
    list.push({ seq: seq, blob: encryptedBlob });

    // Keep only the most recent messages to stay within cache limits.
    if (list.length > TOR_MAX_MESSAGES) {
      list = list.slice(list.length - TOR_MAX_MESSAGES);
    }

    cache.put(boxKey, JSON.stringify(list), ROOM_TTL_SECONDS);
    refreshTorRoomTtl_(room);
    return { ok: true, seq: seq };
  });
}

function gasTorPoll(room, token, box, afterSeq) {
  validateRoom_(room);
  validateAccess_(room, token);
  validateTorBox_(box);

  var after = parseInt(afterSeq, 10);
  if (isNaN(after) || after < 0) { after = 0; }

  var listText = CacheService.getScriptCache().get(key_(room, box));
  var list = [];
  if (listText) {
    try { list = JSON.parse(listText); } catch (err) { list = []; }
  }
  if (!Array.isArray(list)) { list = []; }

  var fresh = [];
  for (var i = 0; i < list.length; i++) {
    if (list[i] && list[i].seq > after) {
      fresh.push(list[i]);
    }
  }

  return { ok: true, messages: fresh, ttl: ROOM_TTL_SECONDS };
}

function gasTorDeleteRoom(room, token) {
  validateRoom_(room);

  var cache = CacheService.getScriptCache();
  var metaText = cache.get(key_(room, 'meta'));
  if (metaText) {
    validateAccess_(room, token);
  }

  cache.put(key_(room, 'used'), '1', ROOM_TTL_SECONDS);
  cache.remove(key_(room, 'meta'));
  cache.remove(key_(room, 'a2b'));
  cache.remove(key_(room, 'b2a'));
  cache.remove(key_(room, 'joined'));

  return { ok: true };
}

function validateTorBox_(box) {
  if (box !== 'a2b' && box !== 'b2a') {
    throw new Error('invalid mailbox.');
  }
}

function validateTorBlob_(blob) {
  if (typeof blob !== 'string') {
    throw new Error('invalid message.');
  }
  if (blob.length < 16 || blob.length > TOR_MAX_BLOB_CHARS) {
    throw new Error('message size is invalid.');
  }
  if (!BLOB_RE.test(blob)) {
    throw new Error('message format is invalid.');
  }
}

function validateRoom_(room) {
  if (typeof room !== 'string' || !ROOM_RE.test(room)) {
    throw new Error('invalid room id.');
  }
}

function validateToken_(token) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
    throw new Error('invalid room token.');
  }
}

function validateBlob_(blob, label) {
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

function validateAccess_(room, token) {
  validateToken_(token);

  var metaText = CacheService.getScriptCache().get(key_(room, 'meta'));
  if (!metaText) {
    throw new Error('room expired or not found.');
  }

  var meta = null;
  try {
    meta = JSON.parse(metaText);
  } catch (err) {
    throw new Error('room data is corrupted.');
  }

  if (!meta || meta.app !== WISP_APP || meta.version !== WISP_VERSION) {
    throw new Error('room version is invalid.');
  }

  if (meta.tokenHash !== tokenHash_(token)) {
    throw new Error('wrong room token.');
  }
}

function refreshTorRoomTtl_(room) {
  var cache = CacheService.getScriptCache();

  var metaText = cache.get(key_(room, 'meta'));
  if (metaText) {
    cache.put(key_(room, 'meta'), metaText, ROOM_TTL_SECONDS);
  }

  if (cache.get(key_(room, 'joined'))) {
    cache.put(key_(room, 'joined'), '1', ROOM_TTL_SECONDS);
  }

  var a2b = cache.get(key_(room, 'a2b'));
  if (a2b) {
    cache.put(key_(room, 'a2b'), a2b, ROOM_TTL_SECONDS);
  }

  var b2a = cache.get(key_(room, 'b2a'));
  if (b2a) {
    cache.put(key_(room, 'b2a'), b2a, ROOM_TTL_SECONDS);
  }
}

function tokenHash_(token) {
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, token, Utilities.Charset.UTF_8);
  return Utilities.base64EncodeWebSafe(bytes).replace(/=+$/g, '');
}

function key_(room, part) {
  return 'wisp:' + room + ':' + part;
}

function withLock_(fn) {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    throw new Error('server is busy. try again.');
  }

  try {
    return fn();
  } finally {
    lock.releaseLock();
  }
}

function jsonOutput_(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
