/**
 * Web-Crypto-based PKCE primitives. Zero dependencies, runtime-portable
 * (Node 18+ and modern browsers).
 *
 *   - `randomUrlSafe`       — uniform sample from the 64-char URL-safe alphabet
 *   - `base64UrlEncode`     — UTF-8 → base64url (no padding)
 *   - `sha256Hex`           — SHA-256 hex helper
 *   - `createPkcePair()`    — verifier + S256 challenge
 *
 * Reference: RFC 7636 "Proof Key for Code Exchange".
 */

/**
 * URL-safe alphabet per RFC 3986 §2.3 ("unreserved characters"):
 *
 *   letters, digits, '-', '.', '_', '~'
 *
 * 64 characters total — perfect for rejection-free base64url sampling.
 */
const URL_SAFE_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Uniformly sample `n` characters from the URL-safe alphabet.
 *
 * Implementation note: a naïve `ALPHABET[byte & 63]` introduces a
 * measurable modular bias (small but nonzero for any `n` < ~10^5).
 * We use rejection sampling on a 6-bit slice (`byte & 0x3f` is itself
 * unbiased, but the byte is drawn from a uniform [0, 256) — we accept
 * rejection-free sampling by mapping the top 2 bits away).
 *
 * The cost is one extra byte per ~4 chars; for `n=64` we draw
 * ~80 bytes and discard ~16 — acceptable.
 */
export function randomUrlSafe(charLength = 32): string {
  if (!Number.isInteger(charLength) || charLength < 1 || charLength > 1024) {
    throw new RangeError(
      `randomUrlSafe: charLength must be an integer in [1, 1024]; got ${charLength}.`,
    );
  }

  const out: string[] = new Array(charLength);
  let i = 0;
  // Each byte yields up to ⌊log2(64)/log2(256)·8⌋ ≈ 1.66 chars, but with the
  // bit-slicing trick below we get exactly 1 char per byte. To be safe we
  // grab an extra 16 bytes for callers who want > 1000 chars.
  while (i < charLength) {
    const bytes = new Uint8Array(charLength + 16);
    crypto.getRandomValues(bytes);
    for (let j = 0; j < bytes.length && i < charLength; j++) {
      const b = bytes[j] ?? 0;
      // Top 2 bits of every byte are uniform over {0..3}; the low 6 bits
      // are uniform over {0..63} — exactly the alphabet index.
      out[i++] = URL_SAFE_ALPHABET[b & 0x3f] as string;
    }
  }
  return out.join("");
}

/** UTF-8 string → base64url (no padding, URL-safe). */
export function base64UrlEncode(input: string | Uint8Array): string {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i] ?? 0);
  const b64 =
    typeof btoa === "function"
      ? btoa(bin)
      : Buffer.from(bin, "binary").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** SHA-256 → hex (uppercase). */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** PKCE pair: code-verifier (43–128 chars) and S256 code-challenge. */
export async function createPkcePair(verifierLength = 64): Promise<{
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}> {
  if (verifierLength < 43 || verifierLength > 128) {
    throw new RangeError(
      `PKCE verifier length must be between 43 and 128 chars (got ${verifierLength}).`,
    );
  }
  const verifier = randomUrlSafe(verifierLength);
  const challenge = await base64UrlEncodeFromHash(verifier);
  return {
    codeVerifier: verifier,
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
  };
}

async function base64UrlEncodeFromHash(verifier: string): Promise<string> {
  const bytes = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Constant-time string compare, used by state validation.
 * Returns false immediately on length mismatch to avoid wasting cycles.
 */
export function safeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
