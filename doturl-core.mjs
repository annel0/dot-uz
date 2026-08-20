/*
 * DotURL v0.1 semantic codec + v2 chat-safe transport.
 * Decodes legacy Base81 fragments; new fragments use Base64URL.
 *
 * This module is compression-backend agnostic. Pass an object with:
 *   deflateRaw(data, dictionary?) -> Uint8Array
 *   inflateRaw(data, dictionary?, maxOutput) -> Uint8Array
 */

export class DotURLError extends Error {}
export class DecodeError extends DotURLError {}

export const BASE81_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
  "abcdefghijklmnopqrstuvwxyz" +
  "0123456789" +
  "-._~" +
  "!$&'()*+,;=" +
  ":@/?";

if (BASE81_ALPHABET.length !== 81 || new Set(BASE81_ALPHABET).size !== 81) {
  throw new Error("Invalid Base81 alphabet");
}

const BASE81_INDEX = new Map([...BASE81_ALPHABET].map((c, i) => [c, i]));
const ASCII = new TextEncoder();

const TAG_RAW = 0x00;
const TAG_DECIMAL = 0x01;
const TAG_HEX_LOWER = 0x02;
const TAG_HEX_UPPER = 0x03;
const TAG_PERCENT_UPPER = 0x04;
const TAG_PERCENT_LOWER = 0x05;
const TAG_UUID_LOWER = 0x06;
const TAG_UUID_UPPER = 0x07;
const TAG_IPV4 = 0x08;
const TAG_B64URL = 0x09;
const TAG_B64STD = 0x0a;

const TOKEN_STRINGS_RAW = [
  "https://", "http://", "www.", "://", "localhost",
  ".com", ".org", ".net", ".io", ".dev", ".app", ".ai", ".co",
  ".ru", ".uz", ".uk", ".de", ".fr", ".jp", ".cn", ".me",
  "github.com/", "raw.githubusercontent.com/", "youtube.com/",
  "youtu.be/", "google.com/", "docs.google.com/", "drive.google.com/",
  "reddit.com/", "wikipedia.org/", "api.", "cdn.", "static.",
  "/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/",
  "/users/", "/user/", "/products/", "/product/", "/posts/", "/post/",
  "/search", "/watch", "/images/", "/assets/", "/static/",
  "/wp-content/", "/wp-content/uploads/", "/uploads/", "/download/",
  "/docs/", "/issues/", "/pull/", "/commit/", "/blob/", "/tree/",
  "?utm_source=", "&utm_source=", "utm_source=",
  "?utm_medium=", "&utm_medium=", "utm_medium=",
  "?utm_campaign=", "&utm_campaign=", "utm_campaign=",
  "?utm_content=", "&utm_content=", "utm_content=",
  "?utm_term=", "&utm_term=", "utm_term=",
  "?ref=", "&ref=", "?source=", "&source=",
  "?id=", "&id=", "?page=", "&page=", "?q=", "&q=",
  "?query=", "&query=", "?lang=", "&lang=",
  "?token=", "&token=", "?key=", "&key=",
  "?redirect=", "&redirect=", "redirect_uri=", "callback=",
  "access_token=", "client_id=", "response_type=", "scope=",
  "telegram", "google", "github", "direct", "social", "organic",
  "email", "true", "false", "null", "json", ".json", ".html",
  ".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".svg",
  "%20", "%2F", "%3A", "%3F", "%3D", "%26",
];

// Python uses list(dict.fromkeys(...)).
const TOKEN_STRINGS = [...new Set(TOKEN_STRINGS_RAW)].slice(0, 128);
if (TOKEN_STRINGS.length > 128) throw new Error("Token dictionary too large");

const TOKENS = TOKEN_STRINGS.map((s) => ASCII.encode(s));
const TOKEN_BY_ID = new Map(TOKENS.map((t, i) => [0x80 + i, t]));
const TOKENS_BY_FIRST = new Map();
for (let i = 0; i < TOKENS.length; i++) {
  const tok = TOKENS[i];
  const arr = TOKENS_BY_FIRST.get(tok[0]) || [];
  arr.push([tok, 0x80 + i]);
  TOKENS_BY_FIRST.set(tok[0], arr);
}
for (const arr of TOKENS_BY_FIRST.values()) arr.sort((a, b) => b[0].length - a[0].length);

function concatBytes(parts, totalLength = null) {
  if (totalLength == null) totalLength = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(totalLength);
  let p = 0;
  for (const part of parts) {
    out.set(part, p);
    p += part.length;
  }
  return out;
}

class ByteWriter {
  constructor() {
    this.parts = [];
    this.length = 0;
    this.small = [];
  }
  flushSmall() {
    if (!this.small.length) return;
    const p = Uint8Array.from(this.small);
    this.parts.push(p);
    this.length += p.length;
    this.small = [];
  }
  byte(b) {
    this.small.push(b & 255);
    if (this.small.length >= 1024) this.flushSmall();
  }
  bytes(b) {
    if (!b.length) return;
    this.flushSmall();
    this.parts.push(b instanceof Uint8Array ? b : Uint8Array.from(b));
    this.length += b.length;
  }
  varint(n) {
    this.bytes(uvarint(n));
  }
  finish() {
    this.flushSmall();
    return concatBytes(this.parts, this.length);
  }
}

function asciiBytes(s) {
  return ASCII.encode(s);
}

const ZDICT_PREFIX = asciiBytes(
  "https://http://www..com.org.net.io.dev.app.ai.co.ru.uz" +
  "/api/v1//api/v2//users//products//search/watch" +
  "?utm_source=&utm_medium=&utm_campaign=&utm_content=&utm_term=" +
  "?id=&page=&q=&query=&lang=&token=&redirect=redirect_uri=" +
  "github.com/raw.githubusercontent.com/youtube.com/google.com/" +
  "/wp-content/uploads//assets//static//images/"
);
const pipe = Uint8Array.of(0x7c);
const tokenJoined = [];
for (let i = 0; i < TOKENS.length; i++) {
  if (i) tokenJoined.push(pipe);
  tokenJoined.push(TOKENS[i]);
}
const ZDICT_ALL = concatBytes([ZDICT_PREFIX, ...tokenJoined]);
export const ZDICT = ZDICT_ALL.length > 32768 ? ZDICT_ALL.slice(-32768) : ZDICT_ALL;

const LEGACY_MODE_CHARS = new Map([
  ["raw|0", "R"], ["semantic|0", "S"], ["deflate|0", "Z"],
  ["deflate_semantic|0", "T"], ["deflate_dict|0", "D"], ["deflate_dict_semantic|0", "E"],
  ["raw|1", "r"], ["semantic|1", "s"], ["deflate|1", "z"],
  ["deflate_semantic|1", "t"], ["deflate_dict|1", "d"], ["deflate_dict_semantic|1", "e"],
]);
const LEGACY_CHAR_TO_MODE = new Map([...LEGACY_MODE_CHARS].map(([k, v]) => {
  const [mode, safe] = k.split("|");
  return [v, [mode, safe === "1"]];
}));

// Transport v2: Telegram/chat-safe Base64URL alphabet only.
// First character encodes both compression mode and checksum flag, so there is
// no extra version byte. Legacy v0.1 Base81 mode letters remain decodable.
const TRANSPORT_MODE_CHARS = new Map([
  ["raw|0", "0"], ["semantic|0", "1"], ["deflate|0", "2"],
  ["deflate_semantic|0", "3"], ["deflate_dict|0", "4"], ["deflate_dict_semantic|0", "5"],
  ["raw|1", "6"], ["semantic|1", "7"], ["deflate|1", "8"],
  ["deflate_semantic|1", "9"], ["deflate_dict|1", "A"], ["deflate_dict_semantic|1", "B"],
]);
const TRANSPORT_CHAR_TO_MODE = new Map([...TRANSPORT_MODE_CHARS].map(([k, v]) => {
  const [mode, safe] = k.split("|");
  return [v, [mode, safe === "1"]];
}));

// ---------- UTF-8 with Python's surrogatepass semantics ----------

export function utf8EncodeSurrogatePass(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let cp = str.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < str.length) {
      const lo = str.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        i++;
      }
    }
    if (cp <= 0x7f) out.push(cp);
    else if (cp <= 0x7ff) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp <= 0xffff) {
      // Includes unpaired surrogates, intentionally.
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
    }
  }
  return Uint8Array.from(out);
}

export function utf8DecodeSurrogatePass(bytes) {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i++];
    let cp;
    if (b0 <= 0x7f) cp = b0;
    else if (b0 >= 0xc2 && b0 <= 0xdf) {
      if (i >= bytes.length) throw new DecodeError("invalid UTF-8");
      const b1 = bytes[i++];
      if ((b1 & 0xc0) !== 0x80) throw new DecodeError("invalid UTF-8");
      cp = ((b0 & 0x1f) << 6) | (b1 & 0x3f);
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      if (i + 1 >= bytes.length) throw new DecodeError("invalid UTF-8");
      const b1 = bytes[i++], b2 = bytes[i++];
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80) throw new DecodeError("invalid UTF-8");
      if (b0 === 0xe0 && b1 < 0xa0) throw new DecodeError("overlong UTF-8");
      // ED A0..BF is allowed here for surrogatepass.
      cp = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      if (i + 2 >= bytes.length) throw new DecodeError("invalid UTF-8");
      const b1 = bytes[i++], b2 = bytes[i++], b3 = bytes[i++];
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80 || (b3 & 0xc0) !== 0x80) throw new DecodeError("invalid UTF-8");
      if (b0 === 0xf0 && b1 < 0x90) throw new DecodeError("overlong UTF-8");
      if (b0 === 0xf4 && b1 > 0x8f) throw new DecodeError("UTF-8 code point out of range");
      cp = ((b0 & 7) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
    } else throw new DecodeError("invalid UTF-8");

    if (cp <= 0xffff) out += String.fromCharCode(cp);
    else {
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    }
  }
  return out;
}

// ---------- Varints ----------

export function uvarint(value) {
  let n = typeof value === "bigint" ? value : BigInt(value);
  if (n < 0n) throw new RangeError("negative varint");
  const out = [];
  while (true) {
    const b = Number(n & 0x7fn);
    n >>= 7n;
    if (n) out.push(b | 0x80);
    else { out.push(b); break; }
  }
  return Uint8Array.from(out);
}

function readUvarint(data, pos, maxBits = 63) {
  let value = 0n;
  let shift = 0;
  while (true) {
    if (pos >= data.length) throw new DecodeError("truncated varint");
    const b = data[pos++];
    value |= BigInt(b & 0x7f) << BigInt(shift);
    if (!(b & 0x80)) return [value, pos];
    shift += 7;
    if (shift > maxBits) throw new DecodeError("varint too large");
  }
}

function bigIntToSafeNumber(n, label) {
  if (n < 0n || n > BigInt(Number.MAX_SAFE_INTEGER)) throw new DecodeError(`${label} too large`);
  return Number(n);
}

// ---------- Base81 block codec (wire-compatible with Python) ----------

const B81_BLOCK_BYTES = 64;
const B81_BLOCK_CHARS = 81;

function digitsForBytes(nbytes) {
  if (nbytes === 0) return 0;
  const target = 1n << BigInt(8 * nbytes);
  let p = 1n, d = 0;
  while (p < target) { p *= 81n; d++; }
  return d;
}

const B81_PARTIAL_CHARS = new Map();
const B81_CHARS_TO_PARTIAL = new Map();
for (let n = 1; n < 64; n++) {
  const d = digitsForBytes(n);
  B81_PARTIAL_CHARS.set(n, d);
  B81_CHARS_TO_PARTIAL.set(d, n);
}
if (digitsForBytes(64) !== 81 || B81_CHARS_TO_PARTIAL.size !== 63) {
  throw new Error("Base81 block geometry failure");
}

function bytesBlockToBigInt(block) {
  let n = 0n;
  for (const b of block) n = (n << 8n) | BigInt(b);
  return n;
}

function b81EncodeBlock(block, outChars) {
  let n = bytesBlockToBigInt(block);
  const out = new Array(outChars).fill(BASE81_ALPHABET[0]);
  for (let i = outChars - 1; i >= 0; i--) {
    const r = Number(n % 81n);
    n /= 81n;
    out[i] = BASE81_ALPHABET[r];
  }
  if (n) throw new Error("Base81 block capacity bug");
  return out.join("");
}

export function base81Encode(data) {
  if (!data.length) return "";
  const out = [];
  const full = Math.floor(data.length / B81_BLOCK_BYTES);
  for (let i = 0; i < full; i++) {
    out.push(b81EncodeBlock(data.slice(i * 64, (i + 1) * 64), 81));
  }
  const rem = data.slice(full * 64);
  if (rem.length) out.push(b81EncodeBlock(rem, B81_PARTIAL_CHARS.get(rem.length)));
  return out.join("");
}

function b81DecodeBlock(text, outBytes) {
  let n = 0n;
  for (const ch of text) {
    const v = BASE81_INDEX.get(ch);
    if (v == null) throw new DecodeError(`invalid Base81 character: ${JSON.stringify(ch)}`);
    n = n * 81n + BigInt(v);
  }
  const limit = 1n << BigInt(8 * outBytes);
  if (n >= limit) throw new DecodeError("Base81 block overflow");
  const out = new Uint8Array(outBytes);
  for (let i = outBytes - 1; i >= 0; i--) {
    out[i] = Number(n & 255n);
    n >>= 8n;
  }
  return out;
}

export function base81Decode(text, { maxChars = 2_000_000 } = {}) {
  if (text.length > maxChars) throw new DecodeError("Base81 payload too large");
  if (!text) return new Uint8Array();

  const full = Math.floor(text.length / B81_BLOCK_CHARS);
  const remChars = text.length % B81_BLOCK_CHARS;
  let remBytes = 0;
  if (remChars) {
    remBytes = B81_CHARS_TO_PARTIAL.get(remChars) || 0;
    if (!remBytes) throw new DecodeError("invalid Base81 tail length");
  }

  const parts = [];
  let pos = 0;
  for (let i = 0; i < full; i++) {
    parts.push(b81DecodeBlock(text.slice(pos, pos + 81), 64));
    pos += 81;
  }
  if (remChars) parts.push(b81DecodeBlock(text.slice(pos), remBytes));
  return concatBytes(parts);
}

// ---------- CRC16-CCITT, equivalent to binascii.crc_hqx(seed=0xFFFF) ----------

export function crc16(data, modeName) {
  const prefix = asciiBytes(modeName + "\0");
  let crc = 0xffff;
  const feed = (b) => {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = ((crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1)) & 0xffff;
  };
  for (const b of prefix) feed(b);
  for (const b of data) feed(b);
  return Uint8Array.of((crc >> 8) & 255, crc & 255);
}

// ---------- ASCII scanners ----------

const isDigit = (b) => b >= 48 && b <= 57;
const isHex = (b) => isDigit(b) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102);
const isHexLetter = (b) => (b >= 65 && b <= 70) || (b >= 97 && b <= 102);
const isUpperHexLetter = (b) => b >= 65 && b <= 70;
const isLowerHexLetter = (b) => b >= 97 && b <= 102;
const isB64Url = (b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || isDigit(b) || b === 45 || b === 95;
const isB64Std = (b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || isDigit(b) || b === 43 || b === 47;

function hexNibble(b) {
  if (b >= 48 && b <= 57) return b - 48;
  if (b >= 65 && b <= 70) return b - 55;
  if (b >= 97 && b <= 102) return b - 87;
  return -1;
}

function caseKindAsciiHex(chunk) {
  let hasLetter = false;
  let allUpper = true, allLower = true;
  for (const c of chunk) {
    if (isHexLetter(c)) {
      hasLetter = true;
      if (!isUpperHexLetter(c)) allUpper = false;
      if (!isLowerHexLetter(c)) allLower = false;
    }
  }
  if (!hasLetter) return "upper";
  if (allUpper) return "upper";
  if (allLower) return "lower";
  return null;
}

function startsWithBytes(data, pos, tok) {
  if (pos + tok.length > data.length) return false;
  for (let i = 0; i < tok.length; i++) if (data[pos + i] !== tok[i]) return false;
  return true;
}

function matchUUID(data, pos) {
  if (pos + 36 > data.length) return 0;
  const hyphens = new Set([8, 13, 18, 23]);
  for (let k = 0; k < 36; k++) {
    const b = data[pos + k];
    if (hyphens.has(k)) { if (b !== 45) return 0; }
    else if (!isHex(b)) return 0;
  }
  return 36;
}

function matchPercentRun(data, pos) {
  let p = pos, groups = 0;
  while (p + 2 < data.length && data[p] === 37 && isHex(data[p + 1]) && isHex(data[p + 2])) {
    groups++; p += 3;
  }
  return groups >= 2 ? p - pos : 0;
}

function matchDecimal(data, pos) {
  let p = pos;
  while (p < data.length && isDigit(data[p])) p++;
  return p - pos >= 7 ? p - pos : 0;
}

function matchHexRun(data, pos) {
  let p = pos;
  while (p < data.length && isHex(data[p])) p++;
  return p - pos >= 8 ? p - pos : 0;
}

function matchB64Run(data, pos, pred) {
  let p = pos;
  while (p < data.length && pred(data[p])) p++;
  if (p - pos < 20) return 0;
  let eq = 0;
  while (p < data.length && data[p] === 61 && eq < 2) { p++; eq++; }
  return p - pos;
}

function matchIPv4(data, pos) {
  let p = pos;
  const parts = [];
  for (let part = 0; part < 4; part++) {
    const start = p;
    if (p >= data.length || !isDigit(data[p])) return null;
    if (data[p] === 48) {
      p++;
      if (p < data.length && isDigit(data[p])) return null;
    } else {
      let digits = 0;
      while (p < data.length && isDigit(data[p]) && digits < 3) { p++; digits++; }
      if (p < data.length && isDigit(data[p])) return null;
    }
    const text = String.fromCharCode(...data.slice(start, p));
    const value = Number(text);
    if (value < 0 || value > 255) return null;
    parts.push(value);
    if (part < 3) {
      if (p >= data.length || data[p] !== 46) return null;
      p++;
    }
  }
  const beforeOK = pos === 0 || !(isDigit(data[pos - 1]) || data[pos - 1] === 46);
  const afterOK = p === data.length || !(isDigit(data[p]) || data[p] === 46);
  return beforeOK && afterOK ? { length: p - pos, parts } : null;
}

function packHex(chunk) {
  const odd = chunk.length & 1;
  const out = new Uint8Array((chunk.length + 1) >> 1);
  let src = 0, dst = 0;
  if (odd) out[dst++] = hexNibble(chunk[src++]);
  while (src < chunk.length) out[dst++] = (hexNibble(chunk[src++]) << 4) | hexNibble(chunk[src++]);
  return out;
}

function unpackHex(packed, chars, upper) {
  let s = "";
  for (const b of packed) s += b.toString(16).padStart(2, "0");
  if (chars & 1) s = s.slice(1);
  if (upper) s = s.toUpperCase();
  return asciiBytes(s);
}

function bytesToBinaryString(bytes) {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) s += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return s;
}

function binaryStringToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 255;
  return out;
}

function b64Encode(bytes, urlsafe = false) {
  let s = btoa(bytesToBinaryString(bytes));
  if (urlsafe) s = s.replace(/\+/g, "-").replace(/\//g, "_");
  return s;
}

function b64Decode(s, urlsafe = false) {
  if (urlsafe) s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (s.length % 4)) % 4;
  if (pad === 3) throw new Error("invalid base64 core length");
  s += "=".repeat(pad);
  return binaryStringToBytes(atob(s));
}

export function transportEncode(data) {
  return b64Encode(data, true).replace(/=+$/, "");
}

export function transportDecode(text, { maxChars = 2_000_000 } = {}) {
  if (text.length > maxChars) throw new DecodeError("transport payload too large");
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new DecodeError("invalid transport character");
  try {
    return b64Decode(text, true);
  } catch (error) {
    throw new DecodeError(error?.message || "invalid Base64URL payload");
  }
}

function tryB64(chunk, urlsafe) {
  try {
    const s = String.fromCharCode(...chunk);
    const core = s.replace(/=+$/, "");
    const explicitPad = s.length - core.length;
    if (explicitPad > 2) return null;
    const decoded = b64Decode(core, urlsafe);
    const rebuilt = b64Encode(decoded, urlsafe).replace(/=+$/, "");
    if (rebuilt !== core) return null;
    const natural = b64Encode(decoded, urlsafe);
    if (explicitPad && natural !== s) return null;
    return concatBytes([Uint8Array.of(explicitPad), decoded]);
  } catch {
    return null;
  }
}

// ---------- Semantic codec ----------

export function semanticEncode(data) {
  const out = new ByteWriter();
  let i = 0;

  while (i < data.length) {
    // UUID
    const uuidLen = matchUUID(data, i);
    if (uuidLen) {
      const chunk = data.slice(i, i + uuidLen);
      const hexOnly = Uint8Array.from([...chunk].filter((b) => b !== 45));
      const kind = caseKindAsciiHex(hexOnly);
      if (kind) {
        const packed = packHex(hexOnly);
        const candidateLen = 1 + packed.length;
        if (candidateLen < chunk.length) {
          out.byte(kind === "upper" ? TAG_UUID_UPPER : TAG_UUID_LOWER);
          out.bytes(packed);
          i += uuidLen;
          continue;
        }
      }
    }

    // Percent run
    const percentLen = matchPercentRun(data, i);
    if (percentLen) {
      const chunk = data.slice(i, i + percentLen);
      const hexChars = new Uint8Array((chunk.length / 3) * 2);
      let hp = 0;
      for (let p = 0; p < chunk.length; p += 3) { hexChars[hp++] = chunk[p + 1]; hexChars[hp++] = chunk[p + 2]; }
      const kind = caseKindAsciiHex(hexChars);
      if (kind) {
        const raw = new Uint8Array(chunk.length / 3);
        for (let p = 0, r = 0; p < chunk.length; p += 3, r++) raw[r] = (hexNibble(chunk[p + 1]) << 4) | hexNibble(chunk[p + 2]);
        const candidateLen = 1 + uvarint(raw.length).length + raw.length;
        if (candidateLen < chunk.length) {
          out.byte(kind === "upper" ? TAG_PERCENT_UPPER : TAG_PERCENT_LOWER);
          out.varint(raw.length);
          out.bytes(raw);
          i += percentLen;
          continue;
        }
      }
    }

    // IPv4
    const ipv4 = matchIPv4(data, i);
    if (ipv4 && 5 < ipv4.length) {
      out.byte(TAG_IPV4);
      out.bytes(Uint8Array.from(ipv4.parts));
      i += ipv4.length;
      continue;
    }

    // Decimal
    const decLen = matchDecimal(data, i);
    if (decLen && decLen <= 1000) {
      const chunk = data.slice(i, i + decLen);
      const value = BigInt(String.fromCharCode(...chunk));
      const a = uvarint(decLen), b = uvarint(value);
      if (1 + a.length + b.length < chunk.length) {
        out.byte(TAG_DECIMAL); out.bytes(a); out.bytes(b);
        i += decLen;
        continue;
      }
    }

    // Hex
    const hexLen = matchHexRun(data, i);
    if (hexLen) {
      const chunk = data.slice(i, i + hexLen);
      let hasLetter = false;
      for (const c of chunk) if (isHexLetter(c)) { hasLetter = true; break; }
      if (hasLetter) {
        const kind = caseKindAsciiHex(chunk);
        if (kind) {
          const packed = packHex(chunk);
          const l = uvarint(chunk.length);
          if (1 + l.length + packed.length < chunk.length) {
            out.byte(kind === "upper" ? TAG_HEX_UPPER : TAG_HEX_LOWER);
            out.bytes(l); out.bytes(packed);
            i += hexLen;
            continue;
          }
        }
      }
    }

    // Base64URL
    let b64Len = matchB64Run(data, i, isB64Url);
    if (b64Len) {
      const chunk = data.slice(i, i + b64Len);
      const packed = tryB64(chunk, true);
      if (packed) {
        const l = uvarint(chunk.length);
        if (1 + l.length + packed.length < chunk.length) {
          out.byte(TAG_B64URL); out.bytes(l); out.bytes(packed);
          i += b64Len;
          continue;
        }
      }
    }

    // Base64 standard
    b64Len = matchB64Run(data, i, isB64Std);
    if (b64Len) {
      const chunk = data.slice(i, i + b64Len);
      const packed = tryB64(chunk, false);
      if (packed) {
        const l = uvarint(chunk.length);
        if (1 + l.length + packed.length < chunk.length) {
          out.byte(TAG_B64STD); out.bytes(l); out.bytes(packed);
          i += b64Len;
          continue;
        }
      }
    }

    // Static dictionary, greedy longest.
    const matches = TOKENS_BY_FIRST.get(data[i]);
    if (matches) {
      let found = false;
      for (const [tok, id] of matches) {
        if (startsWithBytes(data, i, tok)) {
          out.byte(id); i += tok.length; found = true; break;
        }
      }
      if (found) continue;
    }

    // Printable ASCII literal.
    const b = data[i];
    if (b >= 0x20 && b <= 0x7e) { out.byte(b); i++; continue; }

    // Raw non-ASCII/control run.
    let j = i + 1;
    while (j < data.length) {
      const bj = data[j];
      if (bj >= 0x20 && bj <= 0x7e) break;
      j++;
    }
    const raw = data.slice(i, j);
    out.byte(TAG_RAW); out.varint(raw.length); out.bytes(raw);
    i = j;
  }

  return out.finish();
}

export function semanticDecode(code, { maxOutput = 1_000_000 } = {}) {
  const out = new ByteWriter();
  let i = 0;
  const ensure = (n) => { if (out.length + out.small.length + n > maxOutput) throw new DecodeError("semantic output exceeds limit"); };

  while (i < code.length) {
    const b = code[i++];
    if (b >= 0x20 && b <= 0x7e) { ensure(1); out.byte(b); continue; }
    if (b >= 0x80) {
      const tok = TOKEN_BY_ID.get(b);
      if (!tok) throw new DecodeError(`unknown token id 0x${b.toString(16)}`);
      ensure(tok.length); out.bytes(tok); continue;
    }

    if (b === TAG_RAW) {
      let v; [v, i] = readUvarint(code, i);
      const len = bigIntToSafeNumber(v, "raw length");
      if (len > maxOutput || i + len > code.length) throw new DecodeError("truncated/oversized raw run");
      ensure(len); out.bytes(code.slice(i, i + len)); i += len; continue;
    }

    if (b === TAG_DECIMAL) {
      let d, value; [d, i] = readUvarint(code, i); [value, i] = readUvarint(code, i, 4096);
      const digits = bigIntToSafeNumber(d, "decimal digit count");
      let s = value.toString();
      if (s.length > digits || digits > maxOutput) throw new DecodeError("decimal digit count inconsistent");
      s = s.padStart(digits, "0"); ensure(s.length); out.bytes(asciiBytes(s)); continue;
    }

    if (b === TAG_HEX_LOWER || b === TAG_HEX_UPPER) {
      let c; [c, i] = readUvarint(code, i);
      const chars = bigIntToSafeNumber(c, "hex char count");
      if (chars <= 0 || chars > maxOutput) throw new DecodeError("invalid hex char count");
      const nbytes = Math.floor((chars + 1) / 2);
      if (i + nbytes > code.length) throw new DecodeError("truncated hex run");
      const bytes = unpackHex(code.slice(i, i + nbytes), chars, b === TAG_HEX_UPPER);
      i += nbytes; ensure(bytes.length); out.bytes(bytes); continue;
    }

    if (b === TAG_PERCENT_UPPER || b === TAG_PERCENT_LOWER) {
      let c; [c, i] = readUvarint(code, i);
      const count = bigIntToSafeNumber(c, "percent count");
      if (count > maxOutput || i + count > code.length) throw new DecodeError("truncated/oversized percent run");
      ensure(count * 3);
      let s = "";
      const upper = b === TAG_PERCENT_UPPER;
      for (const x of code.slice(i, i + count)) s += "%" + x.toString(16).padStart(2, "0")[upper ? "toUpperCase" : "toLowerCase"]();
      i += count; out.bytes(asciiBytes(s)); continue;
    }

    if (b === TAG_UUID_LOWER || b === TAG_UUID_UPPER) {
      if (i + 16 > code.length) throw new DecodeError("truncated UUID");
      let h = [...code.slice(i, i + 16)].map((x) => x.toString(16).padStart(2, "0")).join("");
      i += 16; if (b === TAG_UUID_UPPER) h = h.toUpperCase();
      const s = `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
      ensure(36); out.bytes(asciiBytes(s)); continue;
    }

    if (b === TAG_IPV4) {
      if (i + 4 > code.length) throw new DecodeError("truncated IPv4");
      const s = [...code.slice(i, i + 4)].join("."); i += 4;
      ensure(s.length); out.bytes(asciiBytes(s)); continue;
    }

    if (b === TAG_B64URL || b === TAG_B64STD) {
      let ol; [ol, i] = readUvarint(code, i);
      const origLen = bigIntToSafeNumber(ol, "base64 original length");
      if (i >= code.length) throw new DecodeError("truncated base64 metadata");
      const explicitPad = code[i++];
      if (explicitPad > 2) throw new DecodeError("invalid base64 padding");
      const coreLen = origLen - explicitPad;
      if (coreLen < 0) throw new DecodeError("invalid base64 original length");
      const missingPad = (4 - (coreLen % 4)) % 4;
      if (missingPad === 3) throw new DecodeError("invalid base64 core length");
      const decodedLen = ((coreLen + missingPad) / 4) * 3 - missingPad;
      if (decodedLen < 0 || i + decodedLen > code.length) throw new DecodeError("truncated base64 payload");
      let enc = b64Encode(code.slice(i, i + decodedLen), b === TAG_B64URL);
      i += decodedLen;
      if (explicitPad === 0) enc = enc.replace(/=+$/, "");
      if (enc.length !== origLen) throw new DecodeError("base64 length mismatch");
      ensure(enc.length); out.bytes(asciiBytes(enc)); continue;
    }

    throw new DecodeError(`unknown semantic tag 0x${b.toString(16)}`);
  }

  return out.finish();
}



// ---------- LZQ: URL-safe Lempel-Ziv bytecode ----------
//
// This is a general tiny bytecode, not a SELF opcode. A program consists of
// three-character instruction headers using the Base64URL alphabet:
//
//   Lxy<data>  literal: copy the next N program bytes to output
//   Rxy        repeat:  copy the last N output bytes once
//   Bxy<data>  base64 literal: decode the next N Base64URL chars to output
//
// x/y encode a 12-bit unsigned length. This is enough to construct genuine
// LZ quines: programs whose output contains the program itself.

const LZQ_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LZQ_INDEX = new Map([...LZQ_ALPHABET].map((c, i) => [c, i]));

function lzqLength(a, b) {
  const hi = LZQ_INDEX.get(a), lo = LZQ_INDEX.get(b);
  if (hi === undefined || lo === undefined) throw new DecodeError("invalid LZQ length");
  return (hi << 6) | lo;
}

export function lzqDecode(program, { maxOutput = 1_000_000 } = {}) {
  if (typeof program !== "string") throw new DecodeError("LZQ program must be text");
  if (!/^[A-Za-z0-9_-]*$/.test(program)) throw new DecodeError("invalid LZQ character");

  const source = asciiBytes(program);
  const out = [];
  let outLen = 0;
  let i = 0;

  const append = (bytes) => {
    if (outLen + bytes.length > maxOutput) throw new DecodeError("LZQ output exceeds limit");
    out.push(bytes);
    outLen += bytes.length;
  };

  const flatten = () => {
    const merged = new Uint8Array(outLen);
    let off = 0;
    for (const chunk of out) { merged.set(chunk, off); off += chunk.length; }
    return merged;
  };

  while (i < source.length) {
    if (i + 3 > source.length) throw new DecodeError("truncated LZQ instruction");
    const op = String.fromCharCode(source[i]);
    const n = lzqLength(String.fromCharCode(source[i + 1]), String.fromCharCode(source[i + 2]));
    i += 3;

    if (op === "L") {
      if (i + n > source.length) throw new DecodeError("truncated LZQ literal");
      append(source.slice(i, i + n));
      i += n;
      continue;
    }

    if (op === "B") {
      if (i + n > source.length) throw new DecodeError("truncated LZQ base64 literal");
      const text = String.fromCharCode(...source.slice(i, i + n));
      i += n;
      try { append(b64Decode(text, true)); }
      catch { throw new DecodeError("invalid LZQ base64 literal"); }
      continue;
    }

    if (op === "R") {
      if (n > outLen) throw new DecodeError("invalid LZQ repeat distance");
      if (n === 0) continue;
      const current = flatten();
      append(current.slice(current.length - n));
      continue;
    }

    throw new DecodeError(`unknown LZQ opcode ${op}`);
  }

  return utf8DecodeSurrogatePass(flatten());
}

export function lzqDecodeFragment(fragment, options = {}) {
  if (!fragment || fragment[0] !== "C") throw new DecodeError("not an LZQ fragment");
  return lzqDecode(fragment.slice(1), options);
}

// ---------- Top-level codec ----------

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function createDotURLCodec(backend) {
  if (!backend || typeof backend.deflateRaw !== "function" || typeof backend.inflateRaw !== "function") {
    throw new TypeError("Compression backend must provide deflateRaw/inflateRaw");
  }

  function candidatePayloads(raw) {
    const sem = semanticEncode(raw);
    return {
      sem,
      candidates: [
        ["raw", raw],
        ["semantic", sem],
        ["deflate", backend.deflateRaw(raw, null)],
        ["deflate_semantic", backend.deflateRaw(sem, null)],
        ["deflate_dict", backend.deflateRaw(raw, ZDICT)],
        ["deflate_dict_semantic", backend.deflateRaw(sem, ZDICT)],
      ],
    };
  }

  function encode(url, { safe = false } = {}) {
    const raw = utf8EncodeSurrogatePass(url);
    const { sem, candidates } = candidatePayloads(raw);
    let best = null;
    for (const [mode, payload] of candidates) {
      const finalPayload = safe ? concatBytes([payload, crc16(raw, mode)]) : payload;
      const fragment = TRANSPORT_MODE_CHARS.get(`${mode}|${safe ? 1 : 0}`) + transportEncode(finalPayload);
      const score = [fragment.length, finalPayload.length, mode];
      if (!best || score[0] < best.score[0] ||
        (score[0] === best.score[0] && (score[1] < best.score[1] ||
        (score[1] === best.score[1] && score[2] < best.score[2])))) {
        best = { score, mode, payload, fragment };
      }
    }
    return {
      fragment: best.fragment,
      mode: best.mode,
      safe,
      sourceBytes: raw.length,
      semanticBytes: sem.length,
      payloadBytes: best.payload.length,
    };
  }

  function decode(fragment, { maxOutput = 1_000_000, requireChecksum = false } = {}) {
    if (!fragment) throw new DecodeError("empty fragment");
    // v2 transport uses digit/A/B mode chars + Base64URL. Legacy v0.1 uses
    // R/S/Z/T/D/E (and lowercase safe variants) + Base81.
    const transportInfo = TRANSPORT_CHAR_TO_MODE.get(fragment[0]);
    const legacyInfo = LEGACY_CHAR_TO_MODE.get(fragment[0]);
    const info = transportInfo || legacyInfo;
    if (!info) throw new DecodeError("unknown codec mode");
    const [mode, safe] = info;
    if (requireChecksum && !safe) throw new DecodeError("checksum required");
    let packed = transportInfo
      ? transportDecode(fragment.slice(1))
      : base81Decode(fragment.slice(1));
    let expectedCRC = null;
    if (safe) {
      if (packed.length < 2) throw new DecodeError("truncated checksum");
      expectedCRC = packed.slice(-2);
      packed = packed.slice(0, -2);
    }

    let raw;
    switch (mode) {
      case "raw": raw = packed; break;
      case "semantic": raw = semanticDecode(packed, { maxOutput }); break;
      case "deflate": raw = backend.inflateRaw(packed, null, maxOutput); break;
      case "deflate_semantic": {
        const sem = backend.inflateRaw(packed, null, maxOutput * 2);
        raw = semanticDecode(sem, { maxOutput }); break;
      }
      case "deflate_dict": raw = backend.inflateRaw(packed, ZDICT, maxOutput); break;
      case "deflate_dict_semantic": {
        const sem = backend.inflateRaw(packed, ZDICT, maxOutput * 2);
        raw = semanticDecode(sem, { maxOutput }); break;
      }
      default: throw new DecodeError("unsupported mode");
    }

    if (raw.length > maxOutput) throw new DecodeError("decoded URL exceeds limit");
    if (safe && !equalBytes(crc16(raw, mode), expectedCRC)) throw new DecodeError("CRC16 mismatch");
    return utf8DecodeSurrogatePass(raw);
  }

  return { encode, decode };
}
