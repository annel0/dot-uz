/* Browser adapter for DotURL v0.1. */
import * as pako from "https://cdn.jsdelivr.net/npm/pako@3.0.1/dist/pako.mjs";
import { createDotURLCodec, DecodeError } from "./doturl-core.mjs";

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

const backend = {
  deflateRaw(data, dictionary) {
    const options = {
      level: 9,
      memLevel: 9,
      strategy: 0,
      legacyHash: true,
    };
    if (dictionary) options.dictionary = dictionary;
    return pako.deflateRaw(data, options);
  },

  inflateRaw: pakoInflateRawLimited,
};

export const DotURL = createDotURLCodec(backend);
export { DecodeError };

/**
 * Decode location.hash and redirect only to HTTP(S).
 * Returns true only when a valid DotURL redirect has been started.
 */
export function redirectFromHash({ safeOnly = false, replace = true } = {}) {
  if (!location.hash || location.hash.length <= 1) return false;

  const fragment = location.hash.slice(1);
  let target;

  try {
    target = DotURL.decode(fragment, { requireChecksum: safeOnly });
  } catch {
    return false;
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return false;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return false;
  }

  if (replace) location.replace(target);
  else location.assign(target);
  return true;
}
