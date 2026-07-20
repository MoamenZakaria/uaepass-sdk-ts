/**
 * Tiny, dependency-free `fetch`-based HTTP helper.
 *
 * `HttpClient` knows its base URL, the fetch implementation, and owns
 * all error mapping. Two methods cover nearly every use:
 *
 *   - `request`      → JSON-parsed response body, throws typed errors
 *   - `requestRaw`   → `Response` object for callers needing raw bytes
 *                       (signed PDF downloads). Throws only on network failures.
 *
 * Why a class instead of free functions?
 *   - One fetch injection point — every method uses the constructor-injected fetch
 *   - No duplicate body reads (`response.json()` consumes the body)
 *   - All non-2xx responses become typed `UaePassError` subclasses
 *   - Cancellation via `AbortSignal` is honoured in both code paths
 */

import {
  UaePassError,
  UaePassHttpError,
  UaePassNetworkError,
  UaePassOAuthError,
} from "./errors.js";
import type { AccessTokenError, AccessTokenResponse } from "./types.js";

/** Node 18+ ships `fetch`/`Request`/`Response`/`FormData`/`Headers` globals. */
export type FetchFn = (
  input: string | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface HttpRequestOptions {
  method?: "GET" | "POST" | "DELETE";
  query?: Record<string, string | undefined>;
  /** Pre-formatted URLSearchParams body — sets `application/x-www-form-urlencoded`. */
  formBody?: URLSearchParams;
  /** JSON body — sets `Content-Type: application/json`. */
  jsonBody?: unknown;
  /** `multipart/form-data` body. The string value is the field name (e.g. "code"). */
  multipart?: Record<string, string>;
  headers?: Record<string, string>;
  /** Abort signal forwarded to fetch. */
  signal?: AbortSignal;
  /** Bearer token to send as `Authorization: Bearer <token>`. */
  bearer?: string;
  /** Pre-encoded `Basic …` header value (token endpoint). */
  basicAuth?: string;
}

export class HttpClient {
  /** Read-only — exposed for callers that want to construct companion clients. */
  public readonly fetchFn: FetchFn;

  constructor(
    public readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? (globalThis.fetch as FetchFn | undefined) ?? fetch;
  }

  /** JSON body. Throws on any non-2xx or network error. */
  async request<T = unknown>(opts: HttpRequestOptions = {}): Promise<T> {
    const res = await this.send(opts);
    await this.assertNotError(res);
    if (res.status === 204) return undefined as T;
    const ct = (res.headers.get("content-type") ?? "").toLowerCase();
    if (ct.includes("application/json") || ct.includes("+json")) {
      return (await readJsonOrThrow(res, this.baseUrl)) as T;
    }
    // Non-JSON 2xx — return as text. Caller decides how to coerce.
    return (await res.text()) as unknown as T;
  }

  /** Raw `Response`. Throws only on network failures. Caller inspects status. */
  async requestRaw(opts: HttpRequestOptions = {}): Promise<Response> {
    return this.send(opts);
  }

  /** Raw `Uint8Array` body. Throws on any non-2xx or network error. */
  async requestBytes(opts: HttpRequestOptions = {}): Promise<Uint8Array> {
    const res = await this.send(opts);
    await this.assertNotError(res);
    if (res.status === 204) return new Uint8Array(0);
    return new Uint8Array(await res.arrayBuffer());
  }

  /**
   * `multipart/form-data` POST. The UAE PASS docs show the token
   * endpoint accepting this format; in practice url-encoded works too,
   * but the option exists for deployments that require it.
   */
  async postMultipart<T = unknown>(
    fields: Record<string, string>,
    opts: Omit<HttpRequestOptions, "formBody" | "jsonBody"> = {},
  ): Promise<T> {
    const fd = new FormData();
    for (const [k, v] of Object.entries(fields)) fd.set(k, v);
    const init = this.buildInit({
      ...opts,
      method: "POST",
    });
    init.body = fd as unknown as BodyInit;
    let res: Response;
    try {
      res = await this.fetchFn(this.baseUrl, init);
    } catch (err) {
      throw new UaePassNetworkError(
        `Network request to ${this.baseUrl} failed: ${errMessage(err)}`,
        err,
      );
    }
    await this.assertNotError(res);
    if (res.status === 204) return undefined as T;
    const ct = (res.headers.get("content-type") ?? "").toLowerCase();
    if (ct.includes("application/json") || ct.includes("+json")) {
      return (await res.json()) as T;
    }
    return (await res.text()) as unknown as T;
  }

  // ─────────── internals ───────────

  private async send(opts: HttpRequestOptions): Promise<Response> {
    const init = this.buildInit(opts);
    const url = appendQuery(this.baseUrl, opts.query);
    try {
      return await this.fetchFn(url, init);
    } catch (err) {
      throw new UaePassNetworkError(
        `Network request to ${url} failed: ${errMessage(err)}`,
        err,
      );
    }
  }

  private buildInit(opts: HttpRequestOptions): RequestInit {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (opts.bearer) headers["Authorization"] = `Bearer ${opts.bearer}`;
    if (opts.basicAuth) headers["Authorization"] = `Basic ${opts.basicAuth}`;

    const init: RequestInit = { method: opts.method ?? "GET", headers };
    if (opts.signal) init.signal = opts.signal;
    if (opts.formBody) {
      headers["Content-Type"] =
        "application/x-www-form-urlencoded; charset=UTF-8";
      init.body = opts.formBody.toString();
    } else if (opts.jsonBody !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.jsonBody);
    }
    init.headers = headers;
    return init;
  }

  private async assertNotError(res: Response): Promise<void> {
    if (res.ok) return;
    // OAuth RFC 6749 §5.2 protocol errors
    if (res.status === 400 || res.status === 401) {
      const data = (await res.json().catch(() => undefined)) as
        | { error?: string; error_description?: string }
        | undefined;
      if (data && typeof data === "object" && typeof data.error === "string") {
        throw new UaePassOAuthError(
          classifyOAuthError(data.error),
          data.error,
          data.error_description,
          res.status,
        );
      }
    }
    const body = await res.text().catch(() => "");
    throw new UaePassHttpError(
      res.status,
      `${this.baseUrl} → HTTP ${res.status}`,
      body,
    );
  }
}

// ─────────── module-level pure helpers ───────────

function appendQuery(
  baseUrl: string,
  query?: Record<string, string | undefined>,
): string {
  if (!query || Object.keys(query).length === 0) return baseUrl;
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) usp.set(k, v);
  }
  const sep = baseUrl.includes("?") ? "&" : "?";
  return `${baseUrl}${sep}${usp.toString()}`;
}

/** Convert a record into a `URLSearchParams` (URL-encoded, no nulls). */
export function toFormParams(
  obj: Record<string, string | number | undefined>,
): URLSearchParams {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null) usp.set(k, String(v));
  }
  return usp;
}

/** Encode `clientId:clientSecret` for HTTP Basic auth (RFC 6749 §2.3.1). */
export function basicAuthHeader(
  clientId: string,
  clientSecret: string,
): string {
  const bin = new TextEncoder().encode(`${clientId}:${clientSecret}`);
  let str = "";
  for (let i = 0; i < bin.byteLength; i++) str += String.fromCharCode(bin[i] ?? 0);
  return base64EncodeFromBytes(str);
}

// Pure-JS base64, no Buffer dependency — see crypto.ts for rationale.
const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64EncodeFromBytes(bin: string): string {
  const bytes = new TextEncoder().encode(bin);
  let out = "";
  for (let i = 0; i < bytes.byteLength; i += 3) {
    const b1 = bytes[i] ?? 0;
    const b2 = i + 1 < bytes.byteLength ? (bytes[i + 1] ?? 0) : 0;
    const b3 = i + 2 < bytes.byteLength ? (bytes[i + 2] ?? 0) : 0;
    const t = (b1 << 16) | (b2 << 8) | b3;
    out += BASE64_ALPHABET[(t >> 18) & 0x3f] as string;
    out += BASE64_ALPHABET[(t >> 12) & 0x3f] as string;
    out += i + 1 < bytes.byteLength
      ? (BASE64_ALPHABET[(t >> 6) & 0x3f] as string)
      : "=";
    out += i + 2 < bytes.byteLength ? (BASE64_ALPHABET[t & 0x3f] as string) : "=";
  }
  return out;
}

async function readJsonOrThrow(res: Response, baseUrl: string): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    throw new UaePassError(
      "invalid_response",
      `${baseUrl} responded with non-JSON body where JSON was expected`,
    );
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Narrow an opaque value into the canonical access-token shape. */
export function asAccessTokenResponse(v: unknown): AccessTokenResponse {
  if (!v || typeof v !== "object") {
    throw new UaePassError("invalid_response", "Empty access-token response");
  }
  const r = v as Record<string, unknown>;
  if (typeof r.access_token !== "string" || r.access_token.length === 0) {
    throw new UaePassError(
      "invalid_response",
      "Access-token response missing `access_token`",
    );
  }
  if (r.token_type !== "Bearer") {
    throw new UaePassError(
      "invalid_response",
      `Expected token_type=Bearer, got ${String(r.token_type)}`,
    );
  }
  if (typeof r.expires_in !== "number" || !Number.isFinite(r.expires_in)) {
    throw new UaePassError(
      "invalid_response",
      "Access-token response missing numeric `expires_in`",
    );
  }
  if (typeof r.scope !== "string") {
    throw new UaePassError(
      "invalid_response",
      "Access-token response missing string `scope`",
    );
  }
  const out: AccessTokenResponse = {
    access_token: r.access_token,
    token_type: "Bearer",
    expires_in: r.expires_in,
    scope: r.scope,
  };
  if (typeof r.refresh_token === "string") out.refresh_token = r.refresh_token;
  return out;
}

function classifyOAuthError(
  code: string,
): Exclude<UaePassError["code"], "network" | "http_error" | "state_mismatch" | "missing_code" | "configuration_error" | "invalid_response"> {
  switch (code) {
    case "invalid_request":
    case "invalid_client":
    case "invalid_grant":
    case "unauthorized_client":
    case "unsupported_grant_type":
    case "invalid_scope":
    case "access_denied":
    case "unsupported_response_type":
    case "server_error":
    case "temporarily_unavailable":
      return code;
    default:
      return "invalid_request";
  }
}
