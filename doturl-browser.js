/* DotURL v2 MAX browser adapter.
 *
 * Compression is deliberately asymmetric: creating a short link may spend
 * more CPU, while decoding remains quick. pako is loaded from a CDN with a
 * fallback CDN because GitHub Pages itself has no server-side compressor.
 */
import { createDotURLCodec, DecodeError, lzqDecodeFragment } from "./doturl-core.mjs";

let pako = null;
let lastError = null;
for (const source of [
  "https://cdn.jsdelivr.net/npm/pako@3.0.1/dist/pako.mjs",
  "https://unpkg.com/pako@3.0.1/dist/pako.mjs",
]) {
  try {
    pako = await import(source);
    break;
  } catch (error) {
    lastError = error;
  }
}
if (!pako) throw lastError || new Error("Unable to load pako");

function pakoInflateRawLimited(data, dictionary, maxOutput) {
  const chunks = [];
  let total = 0;
  const options = { raw: true, chunkSize: 16384 };
  if (dictionary) options.dictionary = dictionary;

  const inflator = new pako.Inflate(options);
  inflator.onData = (chunk) => {
    total += chunk.length;
    if (total > maxOutput) throw new DecodeError("DEFLATE output exceeds limit");
    chunks.push(chunk);
  };

  inflator.push(data, true);
  if (inflator.err) {
    throw new DecodeError(`DEFLATE decode failed: ${inflator.msg || inflator.err}`);
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function compareBytes(a, b) {
  if (!b) return -1;
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

const backend = {
  deflateRaw(data, dictionary) {
    // Two different pako match-finders can produce different valid DEFLATE
    // streams. Try both and keep the shorter stream. No wire-format flag is
    // needed because the decoder only sees ordinary DEFLATE.
    let best = null;
    for (const legacyHash of [false, true]) {
      const options = {
        level: 9,
        memLevel: 9,
        strategy: 0,
        legacyHash,
      };
      if (dictionary) options.dictionary = dictionary;
      const candidate = pako.deflateRaw(data, options);
      if (compareBytes(candidate, best) < 0) best = candidate;
    }
    return best;
  },

  inflateRaw: pakoInflateRawLimited,
};

export const DotURL = createDotURLCodec(backend);
export { DecodeError };

/** Decode location.hash and redirect only to HTTP(S). */
export function redirectFromHash({ safeOnly = false, replace = true } = {}) {
  if (!location.hash || location.hash.length <= 1) return false;

  const fragment = location.hash.slice(1);
  let target;
  try {
    // Backward compatibility with the experimental genuine LZQ quine mode.
    target = fragment[0] === "C"
      ? lzqDecodeFragment(fragment)
      : DotURL.decode(fragment, { requireChecksum: safeOnly });
  } catch {
    return false;
  }

  let parsed;
  try { parsed = new URL(target); }
  catch { return false; }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  if (replace) location.replace(target);
  else location.assign(target);
  return true;
}
