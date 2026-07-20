/**
 * Typed error hierarchy for UAE PASS integration failures.
 *
 * `UaePassError` is the base; subclasses map cleanly onto RFC 6749
 * §5.2 "token endpoint" errors and a few SDK-specific categories so
 * callers can branch on `instanceof` rather than parsing strings.
 *
 * Reference: https://docs.uaepass.ae — token endpoint returns
 *   `{ "error": "...", "error_description": "..." }` per RFC 6749 §5.2.
 */

export type UaePassErrorCode =
  // OAuth RFC 6749 §5.2 — token endpoint
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  // OAuth RFC 6749 §4.1.2.1 — authorisation endpoint
  | "access_denied"
  | "unsupported_response_type"
  | "server_error"
  | "temporarily_unavailable"
  // SDK-specific
  | "network"
  | "http_error"
  | "invalid_response"
  | "state_mismatch"
  | "missing_code"
  | "configuration_error";

export interface UaePassErrorInit {
  /** HTTP-style status code (set on network/http/oauth errors only). */
  status?: number;
  /** Original cause (low-level `fetch` exception, etc). */
  cause?: unknown;
}

/**
 * Base class. Direct construction is rare — prefer the typed subclasses —
 * but it's public so consumers can `instanceof UaePassError` against
 * any error this SDK might raise.
 */
export class UaePassError extends Error {
  readonly code: UaePassErrorCode;
  readonly status?: number;

  constructor(code: UaePassErrorCode, message: string, init: UaePassErrorInit = {}) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    if (init.status !== undefined) this.status = init.status;
    // `cause` is ES2022 Error.cause — set defensively so older
    // @types/node builds that don't expose it still work.
    if (init.cause !== undefined) {
      (this as { cause?: unknown }).cause = init.cause;
    }
  }
}

/** Thrown when a fetch rejects (timeout, DNS, TLS, ECONNRESET). */
export class UaePassNetworkError extends UaePassError {
  constructor(message: string, cause?: unknown) {
    super("network", message, cause !== undefined ? { cause } : {});
  }
}

/** Thrown for non-2xx responses that aren't OAuth protocol errors. */
export class UaePassHttpError extends UaePassError {
  readonly bodyText?: string;

  constructor(status: number, message: string, bodyText?: string) {
    super("http_error", message, { status });
    this.name = "UaePassHttpError";
    if (bodyText !== undefined) this.bodyText = bodyText;
  }
}

/** Thrown for RFC 6749 §5.2 protocol errors ({error, error_description}). */
export class UaePassOAuthError extends UaePassError {
  /** Raw `error_description` returned by the OAuth provider, if any. */
  readonly description?: string;

  constructor(
    code: Exclude<
      UaePassErrorCode,
      | "network"
      | "http_error"
      | "state_mismatch"
      | "missing_code"
      | "configuration_error"
      | "invalid_response"
    >,
    message: string,
    description?: string,
    status?: number,
  ) {
    super(code, message, status !== undefined ? { status } : {});
    this.name = "UaePassOAuthError";
    if (description !== undefined) this.description = description;
  }
}

/** CSRF state mismatch on OAuth callback. */
export class UaePassStateError extends UaePassError {
  constructor(message = "OAuth state mismatch — possible CSRF") {
    super("state_mismatch", message);
    this.name = "UaePassStateError";
  }
}

/**
 * Thrown for missing/malformed SDK input (bad config, bad params).
 * Usually a programming bug — should be caught in dev.
 */
export class UaePassConfigurationError extends UaePassError {
  constructor(message: string) {
    super("configuration_error", message);
    this.name = "UaePassConfigurationError";
  }
}

/**
 * Type guard — true for any error this SDK raises.
 * Convenient in `catch (err) { if (isUaePassError(err)) ... }`.
 */
export function isUaePassError(err: unknown): err is UaePassError {
  return err instanceof UaePassError;
}
