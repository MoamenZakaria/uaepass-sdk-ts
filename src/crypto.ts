/**
 * Web-Crypto-based PKCE primitives + URL-safe encoding helpers.
 *
 * Zero dependencies, runtime-portable (Node 18+, Bun, Deno, modern
 * browsers, React Native with `react-native-get-random-values` polyfill).
 *
 *   - `randomUrlSafe`       — uniform sample of `n` chars from the 64-char URL-safe alphabet
 *   - `base64UrlEncode`     — UTF-8 → base64url (no padding, URL-safe)
 *   - `base64Encode`        — UTF-8 → standard base64 (no padding)
 *   - `sha256`, `sha256Hex` — SHA-256 helpers
 *   - `createPkcePair()`    — verifier + S256 challenge
 *
 * Reference: RFC 7636 "Proof Key for Code Exchange (PKCE)".
 *
 * No `Buffer` references anywhere — base64 is implemented directly on
 * `Uint8Array` so the module is safe in runtimes that don't expose
 * Node's Buffer (browsers, React Native).
 */

/**
 * URL-safe alphabet per RFC 3986 §2.3 ("unreserved characters"):
 * letters, digits, '-', '_'. 64 characters exactly.
 */
const URL_SAFE_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Standard base64 alphabet. */
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Uniformly sample `n` characters from the 64-char URL-safe alphabet.
 *
 * Correctness: each input byte is uniform over `[0, 256)`. Taking the
 * low 6 bits (`b & 0x3f`) is a bijection onto `[0, 64)` — uniform.
 * The discarded top 2 bits are independent of the low 6 bits, so we
 * get **exactly one unbiased alphabet index per byte**, no rejection
 * sampling needed. This is the cleanest known sampling trick.
 */
export function randomUrlSafe(charLength = 32): string {
  if (!Number.isInteger(charLength) || charLength < 1 || charLength > 1024) {
    throw new RangeError(
      `randomUrlSafe: charLength must be an integer in [1, 1024]; got ${charLength}.`,
    );
  }
  const out: string[] = new Array(charLength);
  let i = 0;
  // Each byte yields exactly 1 char; with buffer +16, one fill always suffices.
  const bytes = new Uint8Array(charLength + 16);
  crypto.getRandomValues(bytes);
  for (let j = 0; j < bytes.length && i < charLength; j++) {
    out[i++] = URL_SAFE_ALPHABET[(bytes[j] ?? 0) & 0x3f] as string;
  }
  return out.join("");
}

/** Standard base64 (no URL-safe substitutions, no padding). */
export function base64Encode(input: string | Uint8Array): string {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  let out = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i += 3) {
    const b1 = bytes[i] ?? 0;
    const b2 = i + 1 < len ? (bytes[i + 1] ?? 0) : 0;
    const b3 = i + 2 < len ? (bytes[i + 2] ?? 0) : 0;
    const triplet = (b1 << 16) | (b2 << 8) | b3;
    out += BASE64_ALPHABET[(triplet >> 18) & 0x3f] as string;
    out += BASE64_ALPHABET[(triplet >> 12) & 0x3f] as string;
    out += i + 1 < len ? (BASE64_ALPHABET[(triplet >> 6) & 0x3f] as string) : "=";
    out += i + 2 < len ? (BASE64_ALPHABET[triplet & 0x3f] as string) : "=";
  }
  return out;
}

/** UTF-8 → base64url: standard base64, then `+`→`-`, `/`→`_`, strip `=`. */
export function base64UrlEncode(input: string | Uint8Array): string {
  return base64Encode(input).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** SHA-256 → raw bytes (resolves to a 32-byte Uint8Array). */
export async function sha256(input: string | Uint8Array): Promise<Uint8Array> {
  const data =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  // `data.buffer` may be `SharedArrayBuffer` in some host configs,
  // which `crypto.subtle.digest` rejects. Copy into a plain
  // ArrayBuffer-backed view so we never hit that path.
  const plain = new Uint8Array(data.byteLength);
  plain.set(data);
  const digest = await crypto.subtle.digest("SHA-256", plain);
  return new Uint8Array(digest);
}

/** SHA-256 → uppercase hex (66 chars). */
export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const digest = await sha256(input);
  let hex = "";
  for (let i = 0; i < digest.byteLength; i++) {
    hex += (digest[i] ?? 0).toString(16).padStart(2, "0");
  }
  return hex.toUpperCase();
}

/** PKCE pair: code-verifier (43–128 chars) and S256 code-challenge. */
export async function createPkcePair(verifierLength = 64): Promise<{
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}> {
  if (
    !Number.isInteger(verifierLength) ||
    verifierLength < 43 ||
    verifierLength > 128
  ) {
    throw new RangeError(
      `PKCE verifier length must be an integer in [43, 128]; got ${verifierLength}.`,
    );
  }
  const codeVerifier = randomUrlSafe(verifierLength);
  const digest = await sha256(codeVerifier);
  const codeChallenge = base64UrlEncode(digest);
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}

/**
 * Constant-time string compare, used by state validation.
 * Returns false immediately on length mismatch (cheap rejection).
 */
export function safeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
