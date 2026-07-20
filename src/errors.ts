/**
 * Typed error hierarchy for UAE PASS integration failures.
 *
 * `UaePassError` is the base; specific subclasses let callers branch on
 * behavior (`instanceof`) rather than parsing error strings.
 *
 * Reference: https://docs.uaepass.ae — token endpoint returns
 *   { "error": "...", "error_description": "..." } per RFC 6749 §5.2.
 */

export type UaePassErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "access_denied"
  | "unsupported_response_type"
  | "server_error"
  | "temporarily_unavailable"
  | "network"
  | "http_error"
  | "invalid_response"
  | "state_mismatch"
  | "missing_code";

export interface UaePassErrorOptions {
  status?: number;
  cause?: unknown;
}

export class UaePassError extends Error {
  readonly code: UaePassErrorCode;
  readonly status?: number;

  constructor(code: UaePassErrorCode, message: string, options: UaePassErrorOptions = {}) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    if (options.status !== undefined) this.status = options.status;
    // Set `cause` via direct assignment to avoid relying on `Error.cause`
    // lib support — ES2022 typings vary across @types/node versions.
    if (options.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

export class UaePassNetworkError extends UaePassError {
  constructor(message: string, cause?: unknown) {
    super("network", message, { cause });
    this.name = "UaePassNetworkError";
  }
}

export class UaePassHttpError extends UaePassError {
  readonly bodyText?: string;

  constructor(status: number, message: string, bodyText?: string) {
    super("http_error", message, { status });
    this.name = "UaePassHttpError";
    if (bodyText !== undefined) this.bodyText = bodyText;
  }
}

/** Internal helper — re-cast `status` for subclasses that need to set it. */
function setStatus(e: UaePassError, status: number | undefined): void {
  if (status !== undefined) {
    (e as unknown as { status: number }).status = status;
  }
}

export class UaePassOAuthError extends UaePassError {
  /** Raw `error_description` from the OAuth provider, if any. */
  readonly description?: string;

  constructor(
    code: Exclude<UaePassErrorCode, "network" | "http_error" | "state_mismatch" | "missing_code">,
    message: string,
    description?: string,
    status?: number,
  ) {
    super(code, message);
    this.name = "UaePassOAuthError";
    if (description !== undefined) this.description = description;
    setStatus(this, status);
  }
}

export class UaePassStateError extends UaePassError {
  constructor(message = "OAuth state mismatch — possible CSRF") {
    super("state_mismatch", message);
    this.name = "UaePassStateError";
  }
}
