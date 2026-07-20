/**
 * Tiny, dependency-free `fetch`-based HTTP helper.
 *
 * Why a wrapper?
 *   - Uniform error mapping (network vs. HTTP vs. OAuth protocol error).
 *   - Centralised JSON/form handling — UAE PASS token endpoint uses
 *     `application/x-www-form-urlencoded` per RFC 6749 §4.1.3, which is
 *     awkward to hand-roll with bare `fetch`.
 *   - Testability — callers can inject a `fetch` mock via config.
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
  /** Pre-formatted URLSearchParams body (preferred for token calls). */
  formBody?: URLSearchParams;
  /** JSON body — sets `Content-Type: application/json`. */
  jsonBody?: unknown;
  headers?: Record<string, string>;
  /** Abort signal forwarded to fetch. */
  signal?: AbortSignal;
  /** Bearer token to send as `Authorization: Bearer <token>`. */
  bearer?: string;
  /** Basic auth header value (token endpoint). */
  basicAuth?: string;
}

/**
 * Build a URL with optional query string from a base URL and a flat object.
 */
export function buildUrl(
  baseUrl: string,
  query?: Record<string, string | undefined>,
): string {
  if (!query || Object.keys(query).length === 0) return baseUrl;
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) usp.set(k, v);
  }
  return `${baseUrl}?${usp.toString()}`;
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

/** Convenience: encode `client_id:client_secret` per RFC 6749 §2.3.1. */
export function basicAuthHeader(clientId: string, clientSecret: string): string {
  return btoaUTF8(`${clientId}:${clientSecret}`);
}

/** UTF-8 → base64 (standard). Works in Node (Buffer) and browsers (btoa). */
export function btoaUTF8(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i] ?? 0);
  if (typeof btoa === "function") return btoa(bin);
  // Node fallback
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-var-requires
  const Buf: any = (globalThis as any).Buffer;
  if (Buf) return Buf.from(bin, "binary").toString("base64");
  throw new Error("No base64 encoder available in this runtime.");
}

/** Helpful narrowing — proves the SDK only emits known access-token shapes. */
export function asAccessTokenResponse(v: unknown): AccessTokenResponse {
  if (!v || typeof v !== "object" || !("access_token" in v)) {
    throw new UaePassError(
      "invalid_response",
      "Expected an access-token response from UAE PASS",
    );
  }
  return v as AccessTokenResponse;
}

type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "access_denied"
  | "unsupported_response_type"
  | "server_error"
  | "temporarily_unavailable";

function classifyOAuthError(code: string): OAuthErrorCode {
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

export interface ParsedResponse<T> {
  status: number;
  ok: boolean;
  body: T;
  raw: Response;
}

/**
 * Execute a request and return a parsed response — the same shape every
 * variant of request needs. Throws a typed UaePassError on failure.
 */
export async function executeRequest<T = unknown>(
  url: string,
  opts: HttpRequestOptions,
  fetchFn: FetchFn,
): Promise<T> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.bearer) headers["Authorization"] = `Bearer ${opts.bearer}`;
  if (opts.basicAuth) headers["Authorization"] = `Basic ${opts.basicAuth}`;

  const init: RequestInit = { method: opts.method ?? "GET", headers };
  if (opts.signal) init.signal = opts.signal;
  if (opts.formBody) {
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8";
    init.body = opts.formBody.toString();
  } else if (opts.jsonBody !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.jsonBody);
  }
  init.headers = headers;

  const finalUrl = buildUrl(url, opts.query);

  let res: Response;
  try {
    res = await fetchFn(finalUrl, init);
  } catch (err) {
    throw new UaePassNetworkError(
      `Network request to ${finalUrl} failed: ${(err as Error)?.message ?? "unknown error"}`,
      err,
    );
  }

  if (res.ok) {
    if (res.status === 204) return undefined as T;
    const ct = res.headers.get("content-type") ?? "";
    if (ct.includes("application/json")) return (await res.json()) as T;
    return (await res.text()) as unknown as T;
  }

  // OAuth RFC 6749 §5.2 protocol errors
  if (res.status === 400 || res.status === 401) {
    const data = (await res.json().catch(() => undefined)) as
      | AccessTokenError
      | undefined;
    if (data && typeof data === "object" && "error" in data) {
      throw new UaePassOAuthError(
        classifyOAuthError(data.error),
        data.error ?? "oauth_error",
        data.error_description,
        res.status,
      );
    }
  }

  const body = await res.text().catch(() => "");
  throw new UaePassHttpError(
    res.status,
    `UAE PASS request to ${finalUrl} failed with HTTP ${res.status}`,
    body,
  );
}

/**
 * Stream-friendly variant — returns the raw `Response` for callers that
 * need binary payloads (signed PDFs, signatures) without buffering.
 * Throws on network failures but **not** on non-2xx — caller inspects.
 */
export async function executeRawRequest(
  url: string,
  opts: HttpRequestOptions,
  fetchFn: FetchFn,
): Promise<Response> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.bearer) headers["Authorization"] = `Bearer ${opts.bearer}`;
  if (opts.basicAuth) headers["Authorization"] = `Basic ${opts.basicAuth}`;

  const init: RequestInit = { method: opts.method ?? "GET", headers };
  if (opts.signal) init.signal = opts.signal;
  if (opts.formBody) {
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8";
    init.body = opts.formBody.toString();
  } else if (opts.jsonBody !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.jsonBody);
  }
  init.headers = headers;

  const finalUrl = buildUrl(url, opts.query);

  try {
    return await fetchFn(finalUrl, init);
  } catch (err) {
    throw new UaePassNetworkError(
      `Network request to ${finalUrl} failed: ${(err as Error)?.message ?? "unknown error"}`,
      err,
    );
  }
}

/** Stateful wrapper around `executeRequest` so callers can reuse config. */
export class HttpClient {
  constructor(
    public readonly baseUrl: string,
    private readonly fetchFn: FetchFn = fetch,
  ) {}

  request<T>(opts: HttpRequestOptions = {}): Promise<T> {
    return executeRequest<T>(this.baseUrl, opts, this.fetchFn);
  }

  requestRaw(opts: HttpRequestOptions = {}): Promise<Response> {
    return executeRawRequest(this.baseUrl, opts, this.fetchFn);
  }

  postForm<T>(form: Record<string, string>): Promise<T> {
    const fd = new FormData();
    for (const [k, v] of Object.entries(form)) fd.set(k, v);
    return (async () => {
      let res: Response;
      try {
        res = await this.fetchFn(this.baseUrl, {
          method: "POST",
          body: fd as unknown as BodyInit,
        });
      } catch (err) {
        throw new UaePassNetworkError(
          `Network request to ${this.baseUrl} failed: ${(err as Error)?.message ?? "unknown error"}`,
          err,
        );
      }
      if (res.ok) {
        if (res.status === 204) return undefined as T;
        return (await res.json()) as T;
      }
      if (res.status === 400 || res.status === 401) {
        const data = (await res.json().catch(() => undefined)) as
          | AccessTokenError
          | undefined;
        if (data && typeof data === "object" && "error" in data) {
          throw new UaePassOAuthError(
            classifyOAuthError(data.error),
            data.error ?? "oauth_error",
            data.error_description,
            res.status,
          );
        }
      }
      const body = await res.text().catch(() => "");
      throw new UaePassHttpError(
        res.status,
        `UAE PASS request to ${this.baseUrl} failed with HTTP ${res.status}`,
        body,
      );
    })();
  }
}
