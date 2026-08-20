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
  // DotURL v2 optimizer modes. C is reserved for the LZQ quine format.
  ["semantic2|0", "F"], ["huffman2|0", "G"], ["deflate_semantic2|0", "H"],
  ["semantic2|1", "I"], ["huffman2|1", "J"], ["deflate_semantic2|1", "K"],
  ["deflate_dict_semantic2|0", "L"], ["deflate_dict_semantic2|1", "M"],
  ["rans2|0", "N"], ["rans2|1", "O"],
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
    const decoded = b64Decode(text, true);
    // Reject non-canonical encodings whose unused trailing bits can be changed
    // without changing decoded bytes. This gives every payload one unique text.
    if (transportEncode(decoded) !== text) throw new DecodeError("non-canonical Base64URL payload");
    return decoded;
  } catch (error) {
    if (error instanceof DecodeError) throw error;
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




// ---------- DotURL v2 optimizer semantic bytecode ----------
//
// v2 adds three things on top of the legacy semantic codec:
//   1. a much larger static URL dictionary;
//   2. dynamic LZ backreferences to earlier decoded URL bytes;
//   3. global shortest-path parsing instead of greedy tokenization.
//
// The decoder dictionary may be large because it lives once on the website;
// payload size is the metric we optimize.

const S2_TAG_COPY = 0x0b;
const S2_TAG_EXT = 0x0d;
const S2_TAG_URL5 = 0x10;
const S2_TAG_URL6 = 0x11;

const S2_CORE_RAW = [
  "%25", "https://", ".co", ".com",
  "utm_campaign=", "utm_medium=", "utm_term=", "utm_content=",
  "utm_source=", "&utm_medium=", "&utm_campaign=", "&utm_term=",
  "&utm_content=", "direct", "timestamp=", "access_token=",
  "&timestamp=", "?utm_source=", "/api/", "/users/",
  "github", "api.", "https://api.example.com/", "https://api.",
  "github.com/", "https://github.com/", "https://example.com/", "/watch",
  "/download/", "scope=", "filter=", "client_id=",
  "offset=", "product_id=", "user_id=", "sort=",
  "callback=", "redirect_uri=", "limit=", "cursor=",
  "cdn.", "/v1/", "https://cdn.example.com/", "https://cdn.",
  "&key=", "&filter=", "&query=", "&product_id=",
  "&q=", "&offset=", "&user_id=", "&token=",
  "email", "&sort=", "&callback=", "?q=",
  "&limit=", "&cursor=", "&id=", "&utm_source=",
  "&lang=", "youtube.com/", "/v2/", "&page=",
  "google", "https://shop.example.com/", "https://www.youtube.com/", "https://www.",
  "www.", "/api/v1/", "/api/v1/users/", "organic",
  "/issues/", "/api/v2/", "/commit/", "telegram",
  "/tree/", "/api/v2/users/", "/blob/", "social",
  ".uz", "https://news.example.com/", "/pull/", "/search",
  "/checkout", "?utm_source=email&utm_medium=", "?utm_source=google&utm_medium=", "?utm_source=telegram&utm_medium=",
  "/uploads/", "/news/", "/products/", "/wp-content/",
  "/catalog/", "/account/", "/docs/", "/settings/",
  "/category/", "/assets/", "/static/", "/profile/",
  "/article/", "/images/", "reddit.com/", "https://reddit.com/",
  "google.com/", "wikipedia.org/", ".org", "https://google.com/",
  "https://youtube.com/", "https://wikipedia.org/", "http://", "false",
  "null", "true", "?key=", "?utm_campaign=",
  "?sort=", "?offset=", "?query=", "?utm_term=",
  "?utm_medium=", "?filter=", "?user_id=", "?id=",
  "?utm_content=", "?callback=", "?timestamp=", "?lang=",
];

// Extended entries cost TAG_EXT + varint(id), normally 2-3 bytes. Even a
// two-byte code is a large win for domains, route names and query keys.
const S2_EXT_RAW = [
  "?cursor=", "?token=", "?product_id=", "?page=",
  "127.0.0.1:", "?limit=", "/wp-content/uploads/", ".md",
  ".uk", ".by", ".ch", ".ru",
  ".js", ".cn", ".tv", ".es",
  ".kz", ".se", ".no", ".fi",
  ".dk", "localhost", ".io", ".ai",
  ".de", ".fr", ".jp", ".me",
  ".us", ".ca", ".au", ".br",
  ".it", "https://raw.githubusercontent.com/", "application/x-www-form-urlencoded", "https://cdnjs.cloudflare.com/",
  "https://www.cloudflare.com/", "https://www.instagram.com/", "raw.githubusercontent.com/", "https://drive.google.com/",
  "https://en.wikipedia.org/", "https://www.facebook.com/", "https://www.linkedin.com/", "https://cdn.jsdelivr.net/",
  "/wp-content/uploads/2026/", "https://docs.google.com/", "https://api.github.com/", "https://www.google.com/",
  "https://www.reddit.com/", "https://huggingface.co/", "https://cloudflare.com/", "googleusercontent.com/",
  "githubusercontent.com/", "developer.mozilla.org/", "https://supabase.com/", "cdnjs.cloudflare.com/",
  "fonts.googleapis.com/", "news.ycombinator.com/", "https://twitter.com/", "https://chatgpt.com/",
  "https://openai.com/", "https://vercel.com/", "registry.npmjs.org/", "https://unpkg.com/",
  "stackoverflow.com/", "oneDrive.live.com/", "onedrive.live.com/", "sheets.google.com/",
  "azurewebsites.net/", "fonts.gstatic.com/", "https://youtu.be/", "/api/v1/products/",
  "/api/v2/products/", "drive.google.com/", "digitalocean.com/", "docs.google.com/",
  "maps.google.com/", "tripadvisor.com/", "ycombinator.com/", "firebaseapp.com/",
  "application/json", "https://static.", "huggingface.co/", "cloudflare.com/",
  "googleapis.com/", "aliexpress.com/", "soundcloud.com/", "rfc-editor.org/",
  "aws.amazon.com/", "cloudfront.net/", "firebaseio.com/", "https://x.com/",
  "response_type=", "microsoft.com/", "instagram.com/", "bitbucket.org/",
  "wordpress.com/", "wordpress.org/", "myshopify.com/", "archlinux.org/",
  "rust-lang.org/", "kubernetes.io/", "hashicorp.com/", "amazonaws.com/",
  "/contributors/", "authorization=", "https%3A%2F%2F", "https%3a%2f%2f",
  "https://t.me/", "facebook.com/", "linkedin.com/", "jsdelivr.net/",
  "gravatar.com/", "terraform.io/", "/collections/", "/discussions/",
  "?campaign_id=", "&campaign_id=", "?category_id=", "&category_id=",
  "http%3A%2F%2F", "http%3a%2f%2f", "chatgpt.com/", "twitter.com/",
  "discord.com/", "notion.site/", "dropbox.com/", "gstatic.com/",
  "windows.net/", "shopify.com/", "booking.com/", "netflix.com/",
  "spotify.com/", "archive.org/", "mozilla.org/", "hetzner.com/",
  "workers.dev/", "supabase.co/", "railway.app/", "/categories/",
  "/collection/", "/repository/", "/milestones/", "?session_id=",
  "&session_id=", "?return_url=", "&return_url=", "category_id=",
  "http://www.", "openai.com/", "vercel.app/", "amazon.com/",
  "discord.gg/", "tiktok.com/", "medium.com/", "office.com/",
  "gitlab.com/", "docker.com/", "stripe.com/", "paypal.com/",
  "airbnb.com/", "ubuntu.com/", "debian.org/", "kernel.org/",
  "python.org/", "nodejs.org/", "oracle.com/", "linode.com/",
  "render.com/", "/dashboard/", "/index.html", "/workflows/",
  "?signature=", "&signature=", "session_id=", "return_url=",
  "sitemap.xml", "npmjs.com/", "apple.com/", "notion.so/",
  "azure.com/", "github.io/", "docker.io/", "unpkg.com/",
  "twitch.tv/", "vimeo.com/", "pages.dev/", "localhost:",
  "/articles/", "/releases/", "/branches/", "/projects/",
  "?campaign=", "&campaign=", "?order_id=", "&order_id=",
  "?continue=", "&continue=", "?download=", "&download=",
  "signature=", "index.html", "robots.txt", "/product/",
  "youtu.be/", "pypi.org/", "live.com/", "ebay.com/",
  "ietf.org/", "java.com/", "/graphql/", "/register",
  "/release/", "/archive/", "/compare/", "/actions/",
  "/commits/", "/playlist", "/channel/", "?msclkid=",
  "&msclkid=", "?content=", "&content=", "?session=",
  "&session=", "?post_id=", "&post_id=", "?expires=",
  "&expires=", "?quality=", "&quality=", "order_id=",
  "continue=", "%3A%2F%2F", "%3a%2f%2f", "Bearer%20",
  "index.php", "?source=", "&source=", "quay.io/",
  "helm.sh/", "ovh.com/", "/api/v3/", "/api/v4/",
  "/graphql", "/oauth2/", "/orders/", "/videos/",
  "/source/", "/branch/", "/shorts/", "?utm_id=",
  "&utm_id=", "?fbclid=", "&fbclid=", "?medium=",
  "&medium=", "?format=", "&format=", "?action=",
  "&action=", "?return=", "&return=", "?height=",
  "&height=", "msclkid=", "post_id=", "expires=",
  "api_key=", ".website", "static.", "/posts/",
  "wp.com/", "w3.org/", "go.dev/", "/oauth/",
  "/logout", "/signin", "/signup", "/admin/",
  "/order/", "/items/", "/files/", "/media/",
  "/video/", "/audio/", "/image/", "/fonts/",
  "/build/", "/repos/", "/pulls/", "/embed/",
  "?gclid=", "&gclid=", "?yclid=", "&yclid=",
  "?order=", "&order=", "?state=", "&state=",
  "?nonce=", "&nonce=", "?width=", "&width=",
  "utm_id=", "fbclid=", "format=", "apikey=",
  ".tar.gz", ".online", ".agency", "/user/",
  "/post/", "x.com/", "w.org/", "/rest/",
  "/auth/", "/login", "/item/", "/blog/",
  "/tags/", "/file/", "/dist/", "/runs/",
  "/wiki/", "?term=", "&term=", "?type=",
  "&type=", "?next=", "&next=", "?code=",
  "&code=", "?time=", "&time=", "?date=",
  "&date=", "?from=", "&from=", "?size=",
  "&size=", "gclid=", "yclid=", "order=",
  "bearer", ".woff2", ".cloud", ".store",
  ".space", ".world", "%2F%2F", "%2f%2f",
  "www%2E", "?ref=", "&ref=", ".json",
  ".html", ".jpeg", ".webp", "t.me/",
  "/home", "/cart", "/tag/", "/img/",
  "/css/", "/raw/", "/src/", "?url=",
  "&url=", "?uri=", "&uri=", "?sig=",
  "&sig=", ".webm", ".woff", ".avif",
  ".wasm", ".aspx", ".atom", ".info",
  ".site", ".tech", ".club", ".live",
  ".net", ".dev", ".app", ".css",
  ".png", ".jpg", ".svg", "/js/",
  "?to=", "&to=", ".xml", ".txt",
  ".pdf", ".zip", ".mp4", ".mp3",
  ".ttf", ".ico", ".gif", ".map",
  ".php", ".asp", ".jsp", ".csv",
  ".rss", ".biz", ".xyz", ".pro",
  ".top", "%20", "%2F", "%3A",
  "%3F", "%3D", "%26", "?w=",
  "&w=", "?h=", "&h=", ".gz",
  ".cc", ".in", ".nl", ".pl",
  ".ua", ".eu", "%3d",
];

const S2_CORE_STRINGS = [...new Set(S2_CORE_RAW)].slice(0, 128);
const S2_EXT_STRINGS = [...new Set(S2_EXT_RAW.filter((x) => !S2_CORE_STRINGS.includes(x)))];
const S2_CORE = S2_CORE_STRINGS.map(asciiBytes);
const S2_EXT = S2_EXT_STRINGS.map(asciiBytes);
const S2_CORE_BY_ID = new Map(S2_CORE.map((t, i) => [0x80 + i, t]));
const S2_CORE_BY_FIRST = new Map();
const S2_EXT_BY_FIRST = new Map();
function s2IndexTokens(tokens, target, core) {
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const arr = target.get(tok[0]) || [];
    arr.push(core ? [tok, 0x80 + i] : [tok, i]);
    target.set(tok[0], arr);
  }
  for (const arr of target.values()) arr.sort((a, b) => b[0].length - a[0].length);
}
s2IndexTokens(S2_CORE, S2_CORE_BY_FIRST, true);
s2IndexTokens(S2_EXT, S2_EXT_BY_FIRST, false);

function s2BytesCost(bytes, costTable) {
  if (!costTable) return bytes.length;
  let c = 0;
  for (const b of bytes) c += costTable[b];
  return c;
}

function s2CopyCandidates(data) {
  const n = data.length;
  const edges = Array.from({ length: n }, () => []);
  const seen = new Map();
  const key4 = (i) => (((data[i] << 24) | (data[i+1] << 16) | (data[i+2] << 8) | data[i+3]) >>> 0);

  for (let i = 0; i + 4 <= n; i++) {
    const k = key4(i);
    const arr = seen.get(k) || [];
    const best = [];
    let probes = 0;
    for (let ai = arr.length - 1; ai >= 0 && probes < 16; ai--, probes++) {
      const p = arr[ai];
      const dist = i - p;
      if (dist <= 0) continue;
      let max = 4;
      const maxAllowed = Math.min(4095, n - i);
      while (max < maxAllowed && data[p + (max % dist)] === data[i + max]) max++;
      if (max < 4) continue;
      const enc = concatBytes([Uint8Array.of(S2_TAG_COPY), uvarint(dist), uvarint(max)]);
      const gain = max - enc.length;
      if (gain <= 0) continue;
      best.push({ dist, max, gain });
    }
    best.sort((a,b) => b.gain - a.gain || b.max - a.max || a.dist - b.dist);
    const selected = best.slice(0, 3);
    const emitted = new Set();
    for (const m of selected) {
      // Maximal match is usually best. A few strategic shorter endpoints keep
      // the global parser from missing a much better token immediately after it.
      const lens = [m.max];
      for (const x of [8,16,32,64,128,256,512,1024]) {
        if (x >= 4 && x < m.max && m.max - x <= Math.max(32, m.max >> 2)) lens.push(x);
      }
      for (const len of lens) {
        const sig = `${m.dist}:${len}`;
        if (emitted.has(sig)) continue;
        emitted.add(sig);
        const enc = concatBytes([Uint8Array.of(S2_TAG_COPY), uvarint(m.dist), uvarint(len)]);
        if (enc.length < len) edges[i].push({ len, enc, kind: "copy" });
        if (edges[i].length >= 6) break;
      }
      if (edges[i].length >= 6) break;
    }
    arr.push(i);
    if (arr.length > 32) arr.shift();
    seen.set(k, arr);
  }
  return edges;
}


const S2_URL5_ALPHABET = "abcdefghijklmnopqrstuvwxyz-._~/:";
const S2_URL5_INDEX = new Map([...S2_URL5_ALPHABET].map((c,i) => [c.charCodeAt(0), i]));
const S2_URL6_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const S2_URL6_INDEX = new Map([...S2_URL6_ALPHABET].map((c,i) => [c.charCodeAt(0), i]));

function s2PackFixed(data, start, len, index, bitsPerChar) {
  const out = []; let acc = 0, bits = 0;
  for (let i = 0; i < len; i++) {
    const v = index.get(data[start+i]);
    if (v === undefined) return null;
    acc = (acc << bitsPerChar) | v; bits += bitsPerChar;
    while (bits >= 8) {
      bits -= 8; out.push((acc >> bits) & 255);
      acc &= bits ? ((1 << bits) - 1) : 0;
    }
  }
  if (bits) out.push((acc << (8 - bits)) & 255);
  return Uint8Array.from(out);
}

function s2UnpackFixed(bytes, chars, alphabet, bitsPerChar) {
  const out = new Uint8Array(chars); let oi = 0, acc = 0, bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= bitsPerChar && oi < chars) {
      bits -= bitsPerChar;
      const v = (acc >> bits) & ((1 << bitsPerChar) - 1);
      if (v >= alphabet.length) throw new DecodeError("invalid semantic2 packed alphabet value");
      out[oi++] = alphabet.charCodeAt(v);
      acc &= bits ? ((1 << bits) - 1) : 0;
    }
  }
  if (oi !== chars) throw new DecodeError("truncated semantic2 packed alphabet");
  return out;
}

function s2MatchAlphabetRun(data, i, index, max = 4095) {
  let j = i;
  const end = Math.min(data.length, i + max);
  while (j < end && index.has(data[j])) j++;
  return j - i;
}

function s2TypedEdges(data, i) {
  const edges = [];
  const push = (len, enc, kind) => { if (len > 0 && enc.length < len) edges.push({ len, enc, kind }); };

  // Dense literal alphabets. These are useful for arbitrary domain/path labels
  // that are not in the static dictionary and are not valid Base64 strings.
  const url5Len = s2MatchAlphabetRun(data, i, S2_URL5_INDEX);
  if (url5Len >= 7) {
    const packed = s2PackFixed(data, i, url5Len, S2_URL5_INDEX, 5);
    if (packed) push(url5Len, concatBytes([Uint8Array.of(S2_TAG_URL5), uvarint(url5Len), packed]), "url5");
  }
  const url6Len = s2MatchAlphabetRun(data, i, S2_URL6_INDEX);
  if (url6Len >= 12) {
    const packed = s2PackFixed(data, i, url6Len, S2_URL6_INDEX, 6);
    if (packed) push(url6Len, concatBytes([Uint8Array.of(S2_TAG_URL6), uvarint(url6Len), packed]), "url6");
  }

  const uuidLen = matchUUID(data, i);
  if (uuidLen) {
    const chunk = data.slice(i, i + uuidLen);
    const hexOnly = Uint8Array.from([...chunk].filter((b) => b !== 45));
    const kind = caseKindAsciiHex(hexOnly);
    if (kind) push(uuidLen, concatBytes([Uint8Array.of(kind === "upper" ? TAG_UUID_UPPER : TAG_UUID_LOWER), packHex(hexOnly)]), "uuid");
  }

  const percentLen = matchPercentRun(data, i);
  if (percentLen) {
    const chunk = data.slice(i, i + percentLen);
    const hexChars = new Uint8Array((chunk.length / 3) * 2);
    let hp = 0;
    for (let p = 0; p < chunk.length; p += 3) { hexChars[hp++] = chunk[p+1]; hexChars[hp++] = chunk[p+2]; }
    const kind = caseKindAsciiHex(hexChars);
    if (kind) {
      const raw = new Uint8Array(chunk.length / 3);
      for (let p = 0, r = 0; p < chunk.length; p += 3, r++) raw[r] = (hexNibble(chunk[p+1]) << 4) | hexNibble(chunk[p+2]);
      push(percentLen, concatBytes([Uint8Array.of(kind === "upper" ? TAG_PERCENT_UPPER : TAG_PERCENT_LOWER), uvarint(raw.length), raw]), "percent");
    }
  }

  const ipv4 = matchIPv4(data, i);
  if (ipv4) push(ipv4.length, concatBytes([Uint8Array.of(TAG_IPV4), Uint8Array.from(ipv4.parts)]), "ipv4");

  const decLen = matchDecimal(data, i);
  if (decLen && decLen <= 1000) {
    const chunk = data.slice(i, i + decLen);
    const value = BigInt(String.fromCharCode(...chunk));
    push(decLen, concatBytes([Uint8Array.of(TAG_DECIMAL), uvarint(decLen), uvarint(value)]), "decimal");
  }

  const hexLen = matchHexRun(data, i);
  if (hexLen) {
    const chunk = data.slice(i, i + hexLen);
    let hasLetter = false;
    for (const c of chunk) if (isHexLetter(c)) { hasLetter = true; break; }
    if (hasLetter) {
      const kind = caseKindAsciiHex(chunk);
      if (kind) push(hexLen, concatBytes([Uint8Array.of(kind === "upper" ? TAG_HEX_UPPER : TAG_HEX_LOWER), uvarint(chunk.length), packHex(chunk)]), "hex");
    }
  }

  for (const [urlsafe, pred, tag] of [[true, isB64Url, TAG_B64URL], [false, isB64Std, TAG_B64STD]]) {
    const len = matchB64Run(data, i, pred);
    if (len) {
      const chunk = data.slice(i, i + len);
      const packed = tryB64(chunk, urlsafe);
      if (packed) push(len, concatBytes([Uint8Array.of(tag), uvarint(chunk.length), packed]), urlsafe ? "b64url" : "b64");
    }
  }
  return edges;
}

function s2AllEdges(data, i, copyEdges) {
  const edges = [];
  const core = S2_CORE_BY_FIRST.get(data[i]);
  if (core) for (const [tok, id] of core) if (startsWithBytes(data, i, tok)) edges.push({ len: tok.length, enc: Uint8Array.of(id), kind: "core" });
  const ext = S2_EXT_BY_FIRST.get(data[i]);
  if (ext) for (const [tok, id] of ext) if (startsWithBytes(data, i, tok)) edges.push({ len: tok.length, enc: concatBytes([Uint8Array.of(S2_TAG_EXT), uvarint(id)]), kind: "ext" });
  edges.push(...s2TypedEdges(data, i));
  edges.push(...copyEdges[i]);

  const b = data[i];
  if (b >= 0x20 && b <= 0x7e) {
    edges.push({ len: 1, enc: Uint8Array.of(b), kind: "literal" });
  } else {
    // One maximal raw run is optimal for byte cost; for Huffman cost also add
    // short prefixes so a following structured edge is still reachable.
    let j = i + 1;
    while (j < data.length && !(data[j] >= 0x20 && data[j] <= 0x7e)) j++;
    const max = j - i;
    const lens = new Set([max]);
    for (const l of [1,2,3,4,6,8,12,16,24,32,64,128]) if (l <= max) lens.add(l);
    for (const len of lens) edges.push({ len, enc: concatBytes([Uint8Array.of(TAG_RAW), uvarint(len), data.slice(i, i+len)]), kind: "raw" });
  }
  return edges;
}

export function semantic2Encode(data, { costTable = null } = {}) {
  const n = data.length;
  const copies = s2CopyCandidates(data);
  const dp = new Float64Array(n + 1);
  const choice = new Array(n);
  dp[n] = 0;
  for (let i = n - 1; i >= 0; i--) {
    let best = Infinity, bestEdge = null;
    const edges = s2AllEdges(data, i, copies);
    for (const edge of edges) {
      const next = i + edge.len;
      if (next > n) continue;
      const c = s2BytesCost(edge.enc, costTable) + dp[next];
      if (c < best || (c === best && edge.len > (bestEdge?.len || 0))) {
        best = c; bestEdge = edge;
      }
    }
    if (!bestEdge) throw new Error(`semantic2 parser stuck at ${i}`);
    dp[i] = best; choice[i] = bestEdge;
  }
  const out = [];
  for (let i = 0; i < n;) {
    const edge = choice[i]; out.push(edge.enc); i += edge.len;
  }
  return concatBytes(out);
}

export function semantic2Decode(code, { maxOutput = 1_000_000 } = {}) {
  const out = [];
  let i = 0;
  const append = (bytes) => {
    if (out.length + bytes.length > maxOutput) throw new DecodeError("semantic2 output exceeds limit");
    for (const b of bytes) out.push(b);
  };

  while (i < code.length) {
    const b = code[i++];
    if (b >= 0x20 && b <= 0x7e) { append(Uint8Array.of(b)); continue; }
    if (b >= 0x80) {
      const tok = S2_CORE_BY_ID.get(b);
      if (!tok) throw new DecodeError("unknown semantic2 core token");
      append(tok); continue;
    }
    if (b === S2_TAG_EXT) {
      let id; [id, i] = readUvarint(code, i, 31);
      const n = bigIntToSafeNumber(id, "semantic2 ext token id");
      const tok = S2_EXT[n];
      if (!tok) throw new DecodeError("unknown semantic2 ext token");
      append(tok); continue;
    }
    if (b === S2_TAG_COPY) {
      let d, l; [d, i] = readUvarint(code, i, 31); [l, i] = readUvarint(code, i, 31);
      const dist = bigIntToSafeNumber(d, "semantic2 copy distance");
      const len = bigIntToSafeNumber(l, "semantic2 copy length");
      if (dist <= 0 || dist > out.length || len <= 0 || out.length + len > maxOutput) throw new DecodeError("invalid semantic2 copy");
      for (let k = 0; k < len; k++) out.push(out[out.length - dist]);
      continue;
    }
    if (b === TAG_RAW) {
      let v; [v, i] = readUvarint(code, i);
      const len = bigIntToSafeNumber(v, "semantic2 raw length");
      if (len > maxOutput || i + len > code.length) throw new DecodeError("truncated semantic2 raw run");
      append(code.slice(i, i + len)); i += len; continue;
    }
    if (b === TAG_DECIMAL) {
      let d, value; [d, i] = readUvarint(code, i); [value, i] = readUvarint(code, i, 4096);
      const digits = bigIntToSafeNumber(d, "semantic2 decimal digits");
      let str = value.toString();
      if (str.length > digits || digits > maxOutput) throw new DecodeError("semantic2 decimal inconsistent");
      append(asciiBytes(str.padStart(digits, "0"))); continue;
    }
    if (b === TAG_HEX_LOWER || b === TAG_HEX_UPPER) {
      let c; [c, i] = readUvarint(code, i);
      const chars = bigIntToSafeNumber(c, "semantic2 hex chars");
      const nbytes = Math.floor((chars + 1) / 2);
      if (chars <= 0 || i + nbytes > code.length) throw new DecodeError("truncated semantic2 hex");
      append(unpackHex(code.slice(i, i+nbytes), chars, b === TAG_HEX_UPPER)); i += nbytes; continue;
    }
    if (b === TAG_PERCENT_UPPER || b === TAG_PERCENT_LOWER) {
      let c; [c, i] = readUvarint(code, i);
      const count = bigIntToSafeNumber(c, "semantic2 percent count");
      if (i + count > code.length || out.length + count * 3 > maxOutput) throw new DecodeError("truncated semantic2 percent");
      let str = ""; const upper = b === TAG_PERCENT_UPPER;
      for (const x of code.slice(i, i+count)) str += "%" + x.toString(16).padStart(2, "0")[upper ? "toUpperCase" : "toLowerCase"]();
      i += count; append(asciiBytes(str)); continue;
    }
    if (b === TAG_UUID_LOWER || b === TAG_UUID_UPPER) {
      if (i + 16 > code.length) throw new DecodeError("truncated semantic2 UUID");
      let h = [...code.slice(i, i+16)].map((x) => x.toString(16).padStart(2,"0")).join(""); i += 16;
      if (b === TAG_UUID_UPPER) h = h.toUpperCase();
      append(asciiBytes(`${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`)); continue;
    }
    if (b === TAG_IPV4) {
      if (i + 4 > code.length) throw new DecodeError("truncated semantic2 IPv4");
      append(asciiBytes([...code.slice(i,i+4)].join("."))); i += 4; continue;
    }
    if (b === TAG_B64URL || b === TAG_B64STD) {
      let ol; [ol, i] = readUvarint(code, i);
      const origLen = bigIntToSafeNumber(ol, "semantic2 base64 length");
      if (i >= code.length) throw new DecodeError("truncated semantic2 base64 metadata");
      const explicitPad = code[i++];
      if (explicitPad > 2) throw new DecodeError("invalid semantic2 base64 padding");
      const coreLen = origLen - explicitPad; const missingPad = (4 - (coreLen % 4)) % 4;
      if (coreLen < 0 || missingPad === 3) throw new DecodeError("invalid semantic2 base64 length");
      const decodedLen = ((coreLen + missingPad) / 4) * 3 - missingPad;
      if (decodedLen < 0 || i + decodedLen > code.length) throw new DecodeError("truncated semantic2 base64 payload");
      let enc = b64Encode(code.slice(i, i+decodedLen), b === TAG_B64URL); i += decodedLen;
      if (explicitPad === 0) enc = enc.replace(/=+$/, "");
      if (enc.length !== origLen) throw new DecodeError("semantic2 base64 length mismatch");
      append(asciiBytes(enc)); continue;
    }
    if (b === S2_TAG_URL5 || b === S2_TAG_URL6) {
      let c; [c, i] = readUvarint(code, i);
      const chars = bigIntToSafeNumber(c, "semantic2 packed chars");
      if (chars <= 0 || chars > maxOutput) throw new DecodeError("invalid semantic2 packed length");
      const bitsPerChar = b === S2_TAG_URL5 ? 5 : 6;
      const nbytes = Math.ceil(chars * bitsPerChar / 8);
      if (i + nbytes > code.length) throw new DecodeError("truncated semantic2 packed literal");
      const alphabet = b === S2_TAG_URL5 ? S2_URL5_ALPHABET : S2_URL6_ALPHABET;
      append(s2UnpackFixed(code.slice(i, i+nbytes), chars, alphabet, bitsPerChar));
      i += nbytes; continue;
    }
    throw new DecodeError(`unknown semantic2 tag 0x${b.toString(16)}`);
  }
  return Uint8Array.from(out);
}

// Placeholder static Huffman table. A build-time trainer replaces this with a
// corpus-trained canonical table. 9-bit fixed codes are valid for 257 symbols.
export const S2_HUFFMAN_LENGTHS = new Uint8Array([7,7,7,8,7,8,7,8,7,7,7,6,7,8,8,9,7,6,8,9,8,9,9,9,8,9,9,9,9,9,9,9,8,9,5,9,8,9,7,9,8,9,9,8,7,8,7,8,7,7,7,7,7,7,7,7,7,7,7,9,9,7,9,8,8,7,8,8,7,8,8,9,8,9,8,8,9,8,8,8,9,8,9,8,8,8,8,8,8,8,9,9,9,9,9,9,9,7,8,7,7,7,8,8,8,7,8,8,7,8,7,7,7,9,7,7,7,8,8,8,8,8,8,8,9,8,9,9,7,8,8,9,9,9,9,9,8,8,8,8,8,8,9,8,8,8,8,8,9,9,8,9,9,8,8,9,9,8,9,8,9,9,9,9,9,8,9,8,9,9,8,9,8,8,9,8,8,8,8,8,9,8,9,8,8,8,8,8,8,9,8,8,8,9,9,8,9,9,9,9,9,9,9,9,9,9,9,9,7,7,8,9,9,8,9,9,8,9,9,9,9,8,9,9,9,9,9,9,8,9,8,9,8,9,9,9,9,9,9,9,8,9,9,8,9,9,9,9,9,9,9,9,9,9,9,9,7]);

function s2BuildCanonical(lengths) {
  let maxLen = 0;
  const blCount = [];
  for (const l of lengths) { if (l) { blCount[l] = (blCount[l] || 0) + 1; if (l > maxLen) maxLen = l; } }
  const nextCode = []; let code = 0;
  for (let bits = 1; bits <= maxLen; bits++) { code = (code + (blCount[bits-1] || 0)) << 1; nextCode[bits] = code; }
  const codes = new Array(lengths.length);
  for (let sym = 0; sym < lengths.length; sym++) {
    const len = lengths[sym]; if (!len) continue;
    codes[sym] = [nextCode[len]++, len];
  }
  const decode = new Map();
  for (let sym = 0; sym < codes.length; sym++) if (codes[sym]) {
    const [c,l] = codes[sym]; decode.set(`${l}:${c}`, sym);
  }
  return { codes, decode, maxLen };
}
const S2_HUFF = s2BuildCanonical(S2_HUFFMAN_LENGTHS);

export function huffman2Encode(data) {
  const bytes = [];
  let acc = 0, bits = 0;
  const put = (code, len) => {
    for (let k = len - 1; k >= 0; k--) {
      acc = (acc << 1) | ((code >> k) & 1); bits++;
      if (bits === 8) { bytes.push(acc); acc = 0; bits = 0; }
    }
  };
  for (const b of data) { const [c,l] = S2_HUFF.codes[b]; put(c,l); }
  { const [c,l] = S2_HUFF.codes[256]; put(c,l); }
  if (bits) bytes.push(acc << (8 - bits));
  return Uint8Array.from(bytes);
}

export function huffman2Decode(data, { maxOutput = 2_000_000 } = {}) {
  const out = []; let code = 0, len = 0;
  for (const byte of data) {
    for (let k = 7; k >= 0; k--) {
      code = (code << 1) | ((byte >> k) & 1); len++;
      const sym = S2_HUFF.decode.get(`${len}:${code}`);
      if (sym !== undefined) {
        if (sym === 256) return Uint8Array.from(out);
        out.push(sym); if (out.length > maxOutput) throw new DecodeError("Huffman2 output exceeds limit");
        code = 0; len = 0;
      } else if (len > S2_HUFF.maxLen) throw new DecodeError("invalid Huffman2 code");
    }
  }
  throw new DecodeError("Huffman2 EOS missing");
}

// Exposed for the build-time Huffman trainer.
export function semantic2HuffmanOptimizedEncode(data) {
  return semantic2Encode(data, { costTable: S2_HUFFMAN_LENGTHS });
}


// Static rANS model trained on the URL corpus used to build the v2 dictionary.
// It approaches the model entropy more closely than Huffman while keeping the
// decoder table tiny (4096 entries generated at module load time).
export const S2_RANS_FREQ = new Uint16Array([36,36,25,13,36,13,26,12,23,27,32,49,28,15,12,11,25,60,16,11,12,9,10,9,12,9,9,11,9,8,9,9,12,8,106,9,17,11,37,10,13,9,9,16,27,17,28,21,39,41,36,27,27,33,31,26,34,30,37,8,10,35,8,16,13,23,17,14,24,19,15,11,15,12,15,13,10,19,16,13,11,12,11,17,20,12,12,14,17,12,10,8,9,8,8,9,9,40,18,23,24,37,14,19,15,32,14,21,26,16,22,23,26,10,35,30,36,21,19,15,17,18,16,18,9,17,8,10,38,18,16,10,8,11,9,10,13,18,16,17,17,12,9,17,16,13,12,13,10,10,14,10,9,12,18,10,11,13,10,16,9,10,9,10,9,15,10,12,11,11,14,8,16,15,11,13,16,16,12,12,11,18,12,12,21,13,18,17,13,11,12,14,12,11,11,12,10,9,10,11,12,11,9,10,10,10,10,10,43,28,13,9,11,13,10,10,14,11,9,10,11,12,10,9,11,10,11,10,13,11,14,9,12,9,9,10,9,9,10,9,17,9,9,12,11,9,9,10,9,9,9,10,9,9,9,10,25]);
const S2_RANS_SCALE_BITS = 12;
const S2_RANS_TOT = 1 << S2_RANS_SCALE_BITS;
const S2_RANS_L = 1 << 23;
const S2_RANS_CUM = new Uint16Array(257);
const S2_RANS_DECODE = new Uint16Array(S2_RANS_TOT);
{
  let c = 0;
  for (let sym = 0; sym < 257; sym++) {
    S2_RANS_CUM[sym] = c;
    const f = S2_RANS_FREQ[sym];
    for (let x = c; x < c + f; x++) S2_RANS_DECODE[x] = sym;
    c += f;
  }
  if (c !== S2_RANS_TOT) throw new Error("invalid rANS frequency table");
}
export const S2_RANS_COST = new Float64Array([...S2_RANS_FREQ].map((f) => Math.log2(S2_RANS_TOT / f)));

export function rans2Encode(data) {
  // EOS=256 means no length prefix is needed.
  const symbols = new Uint16Array(data.length + 1);
  symbols.set(data, 0); symbols[data.length] = 256;
  let state = S2_RANS_L;
  const emitted = [];
  for (let i = symbols.length - 1; i >= 0; i--) {
    const sym = symbols[i], freq = S2_RANS_FREQ[sym], start = S2_RANS_CUM[sym];
    const xMax = Math.floor(S2_RANS_L / S2_RANS_TOT) * 256 * freq;
    while (state >= xMax) { emitted.push(state & 255); state = Math.floor(state / 256); }
    state = Math.floor(state / freq) * S2_RANS_TOT + (state % freq) + start;
  }
  // Initial state (big endian) + renormalization bytes in decoder order.
  const out = new Uint8Array(4 + emitted.length);
  out[0] = (state >>> 24) & 255; out[1] = (state >>> 16) & 255; out[2] = (state >>> 8) & 255; out[3] = state & 255;
  for (let i = 0; i < emitted.length; i++) out[4 + i] = emitted[emitted.length - 1 - i];
  return out;
}

export function rans2Decode(data, { maxOutput = 2_000_000 } = {}) {
  if (data.length < 4) throw new DecodeError("truncated rANS2 stream");
  let state = (((data[0] * 0x1000000) + (data[1] << 16) + (data[2] << 8) + data[3]) >>> 0);
  if (state < S2_RANS_L) throw new DecodeError("invalid rANS2 initial state");
  let pos = 4; const out = [];
  while (true) {
    const slot = state & (S2_RANS_TOT - 1);
    const sym = S2_RANS_DECODE[slot];
    const freq = S2_RANS_FREQ[sym], start = S2_RANS_CUM[sym];
    state = freq * Math.floor(state / S2_RANS_TOT) + slot - start;
    while (state < S2_RANS_L) {
      if (pos >= data.length) throw new DecodeError("truncated rANS2 renormalization");
      state = state * 256 + data[pos++];
    }
    if (sym === 256) {
      if (pos !== data.length) throw new DecodeError("trailing rANS2 bytes");
      return Uint8Array.from(out);
    }
    out.push(sym);
    if (out.length > maxOutput) throw new DecodeError("rANS2 output exceeds limit");
  }
}

export function semantic2RansOptimizedEncode(data) {
  return semantic2Encode(data, { costTable: S2_RANS_COST });
}

// A byte dictionary for DEFLATE over semantic2 streams. It contains semantic
// encodings of recurring URL templates, not raw URL text.
const S2_DICT_SEEDS = [
  "https://www.google.com/search?q=example&utm_source=google&utm_medium=organic",
  "https://github.com/openai/openai-python/issues/12345",
  "https://www.youtube.com/watch?v=abcdefghijk&utm_source=telegram&utm_medium=social",
  "https://api.example.com/api/v1/users/550e8400-e29b-41d4-a716-446655440000?access_token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "https://example.com/wp-content/uploads/2026/08/image.webp",
  "https://example.com/products/123456789?utm_source=telegram&utm_medium=social&utm_campaign=summer",
  "https://cdn.example.com/assets/static/images/example.webp?width=1200&height=800&quality=90",
  "https://example.com/search?q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82&lang=ru&page=1",
];
export const ZDICT2 = (() => {
  const chunks = [];
  for (const x of S2_DICT_SEEDS) chunks.push(semantic2Encode(utf8EncodeSurrogatePass(x)));
  const all = concatBytes(chunks);
  return all.length > 32768 ? all.slice(-32768) : all;
})();

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
    const sem2 = semantic2Encode(raw);
    const sem2H = semantic2HuffmanOptimizedEncode(raw);
    const huff2 = huffman2Encode(sem2H);
    const def2a = backend.deflateRaw(sem2, null);
    const def2b = equalBytes(sem2, sem2H) ? def2a : backend.deflateRaw(sem2H, null);
    const def2 = def2a.length <= def2b.length ? def2a : def2b;
    const dd2a = backend.deflateRaw(sem2, ZDICT2);
    const dd2b = equalBytes(sem2, sem2H) ? dd2a : backend.deflateRaw(sem2H, ZDICT2);
    const dd2 = dd2a.length <= dd2b.length ? dd2a : dd2b;
    const candidates = [
      ["raw", raw],
      ["semantic", sem],
      ["deflate", backend.deflateRaw(raw, null)],
      ["deflate_semantic", backend.deflateRaw(sem, null)],
      ["deflate_dict", backend.deflateRaw(raw, ZDICT)],
      ["deflate_dict_semantic", backend.deflateRaw(sem, ZDICT)],
      ["semantic2", sem2],
      ["huffman2", huff2],
      ["deflate_semantic2", def2],
      ["deflate_dict_semantic2", dd2],
    ];
    // rANS has a 4-byte initial-state overhead and loses to Huffman on short
    // URLs, but can shave bytes from very large payloads. Pay its extra parse
    // cost only where it can plausibly win.
    if (raw.length >= 4096) {
      const sem2R = semantic2RansOptimizedEncode(raw);
      candidates.push(["rans2", rans2Encode(sem2R)]);
    }
    return { sem, sem2, sem2H, candidates };
  }

  function encode(url, { safe = false } = {}) {
    const raw = utf8EncodeSurrogatePass(url);
    const { sem, sem2, candidates } = candidatePayloads(raw);
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
      semantic2Bytes: sem2.length,
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
      case "semantic2": raw = semantic2Decode(packed, { maxOutput }); break;
      case "huffman2": {
        const sem2 = huffman2Decode(packed, { maxOutput: maxOutput * 3 });
        raw = semantic2Decode(sem2, { maxOutput }); break;
      }
      case "rans2": {
        const sem2 = rans2Decode(packed, { maxOutput: maxOutput * 3 });
        raw = semantic2Decode(sem2, { maxOutput }); break;
      }
      case "deflate_semantic2": {
        const sem2 = backend.inflateRaw(packed, null, maxOutput * 3);
        raw = semantic2Decode(sem2, { maxOutput }); break;
      }
      case "deflate_dict_semantic2": {
        const sem2 = backend.inflateRaw(packed, ZDICT2, maxOutput * 3);
        raw = semantic2Decode(sem2, { maxOutput }); break;
      }
      default: throw new DecodeError("unsupported mode");
    }

    if (raw.length > maxOutput) throw new DecodeError("decoded URL exceeds limit");
    if (safe && !equalBytes(crc16(raw, mode), expectedCRC)) throw new DecodeError("CRC16 mismatch");
    return utf8DecodeSurrogatePass(raw);
  }

  return { encode, decode };
}
