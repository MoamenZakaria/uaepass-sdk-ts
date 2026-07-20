/**
 * UAE PASS digital-signature client.
 *
 * Full single-document flow per docs.uaepass.ae/feature-guides/signature-integration-guide/digital-signature-single-document/signing-guide:
 *
 *   1. User authenticates via /idshub/authorize FIRST — their access
 *      token is forwarded to every signing call.
 *   2. Get a dedicated `trustedx-resources` token via client_credentials.
 *   3. `createSignerProcess({ document, userAccessToken })` → process + document IDs.
 *   4. `getResult(processId)`   → status + signed URLs.
 *   5. `fetchSignedDocument(documentId)` → raw PDF bytes.
 *   6. `deleteProcess(processId)` → cleanup.
 */

import {
  HttpClient,
  basicAuthHeader,
  toFormParams,
  type FetchFn,
} from "./http.js";
import {
  resolveEndpoints,
  type Environment,
  type UaePassEndpoints,
} from "./endpoints.js";
import { UaePassConfigurationError } from "./errors.js";
import type {
  SignatureSigningAccessToken,
  SignatureSignerProcessRequest,
  SignatureSignerProcessResponse,
  SignatureSignerProcessResult,
  SignerStatus,
} from "./types.js";

export interface SignatureClientConfig {
  environment?: Environment;
  clientId: string;
  clientSecret: string;
  /** Override fetch for tests / non-standard runtimes. */
  fetch?: FetchFn;
  endpoints?: UaePassEndpoints;
  /** Default `hashAlgorithm` for `createSignerProcess()`. */
  hashAlgorithm?: SignatureSignerProcessRequest["hashAlgorithm"];
  /**
   * When refreshing a signing token, refresh this many milliseconds
   * *before* the actual expiry to account for clock skew and in-flight
   * requests. Defaults to 60 seconds.
   */
  expirySafetyMs?: number;
}

export interface CreateSignerProcessOptions
  extends Omit<SignatureSignerProcessRequest, "userAccessToken"> {
  /** If omitted, the SDK throws — required for signing. */
  userAccessToken?: string;
}

export interface WaitOptions {
  intervalMs?: number;
  timeoutMs?: number;
}

/**
 * A small in-memory cache for the signing-platform access token.
 * Keeps the token, its absolute expiry, and lets callers invalidate.
 */
interface TokenCache {
  token: SignatureSigningAccessToken;
  /** Absolute expiry timestamp (ms since epoch). */
  expiresAtMs: number;
}

const TERMINAL_STATUSES: ReadonlyArray<SignerStatus> = [
  "COMPLETED",
  "FAILED",
  "EXPIRED",
];

export class SignatureClient {
  private readonly endpoints: UaePassEndpoints;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly tokenHttp: HttpClient;
  private readonly signHttp: HttpClient;
  private readonly expirySafetyMs: number;
  private readonly defaultHashAlgorithm: NonNullable<
    SignatureSignerProcessRequest["hashAlgorithm"]
  >;
  /** Per-instance — never leaked. */
  private cached: TokenCache | null = null;

  constructor(config: SignatureClientConfig) {
    SignatureClient.assertString(config.clientId, "clientId");
    SignatureClient.assertString(config.clientSecret, "clientSecret");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.endpoints =
      config.endpoints ?? resolveEndpoints(config.environment ?? "staging");
    this.defaultHashAlgorithm = config.hashAlgorithm ?? "SHA256";
    this.expirySafetyMs = Math.max(0, config.expirySafetyMs ?? 60_000);

    const fetch = config.fetch ?? defaultFetch();
    this.tokenHttp = new HttpClient(this.endpoints.signingToken, fetch);
    this.signHttp = new HttpClient(this.endpoints.signerProcesses, fetch);
  }

  /**
   * Obtain (or refresh) a signing-platform access token. Caches
   * based on `expires_in` minus a safety margin, so callers don't
   * make a token request on every signing call.
   */
  async getToken(
    scope: string = "urn:uae:digitalid:signature",
  ): Promise<SignatureSigningAccessToken> {
    const now = Date.now();
    if (this.cached && this.cached.expiresAtMs - this.expirySafetyMs > now) {
      return this.cached.token;
    }
    const usp = toFormParams({ grant_type: "client_credentials", scope });
    const fresh = await this.tokenHttp.request<SignatureSigningAccessToken>({
      method: "POST",
      formBody: usp,
      basicAuth: basicAuthHeader(this.clientId, this.clientSecret),
    });
    if (
      typeof fresh.expires_in !== "number" ||
      !Number.isFinite(fresh.expires_in)
    ) {
      throw new UaePassConfigurationError(
        "Signature token response missing numeric `expires_in`",
      );
    }
    this.cached = {
      token: fresh,
      expiresAtMs: now + fresh.expires_in * 1000,
    };
    return fresh;
  }

  /** Force-refresh on the next call (e.g. after a 401 from the platform). */
  invalidateToken(): void {
    this.cached = null;
  }

  /** Step 3 — upload the document and create the signing process. */
  async createSignerProcess(
    opts: CreateSignerProcessOptions,
  ): Promise<SignatureSignerProcessResponse> {
    if (typeof opts.userAccessToken !== "string" || opts.userAccessToken.length === 0) {
      throw new UaePassConfigurationError(
        "`userAccessToken` is required for createSignerProcess.",
      );
    }
    const document = normaliseDocument(opts.document);

    const payload = {
      document: {
        name: document.name,
        content: document.content,
        hashAlgorithm: opts.hashAlgorithm ?? this.defaultHashAlgorithm,
      },
      description: opts.description,
      reason: opts.reason,
      userAccessToken: opts.userAccessToken,
    };

    const token = await this.getToken();
    return this.signHttp.request<SignatureSignerProcessResponse>({
      method: "POST",
      jsonBody: payload,
      bearer: token.access_token,
    });
  }

  /** Step 4 — single-shot status check. */
  async getResult(processId: string): Promise<SignatureSignerProcessResult> {
    if (typeof processId !== "string" || processId.length === 0) {
      throw new UaePassConfigurationError("`processId` is required.");
    }
    const token = await this.getToken();
    return this.signHttp.request<SignatureSignerProcessResult>({
      method: "GET",
      bearer: token.access_token,
    }).catch((err) => {
      // On 401, drop the cached token and let caller retry once with a fresh token.
      // We don't retry automatically to keep the public surface simple.
      if (
        err &&
        typeof err === "object" &&
        "status" in err &&
        (err as { status?: number }).status === 401
      ) {
        this.invalidateToken();
      }
      throw err;
    });
  }

  /** Poll until terminal state or timeout. Honours `AbortSignal`. */
  async waitUntilDone(
    processId: string,
    options: WaitOptions & { signal?: AbortSignal } = {},
  ): Promise<SignatureSignerProcessResult> {
    const intervalMs = SignatureClient.validateInterval(options.intervalMs ?? 2_000);
    const timeoutMs = SignatureClient.validateTimeout(options.timeoutMs ?? 5 * 60_000);
    const signal = options.signal;

    const started = Date.now();
    let last: SignatureSignerProcessResult | undefined;
    while (Date.now() - started < timeoutMs) {
      if (signal?.aborted) {
        throw new Error("waitUntilDone: aborted");
      }
      last = await this.getResult(processId);
      if (TERMINAL_STATUSES.includes(last.status)) return last;
      await delay(intervalMs, signal);
    }
    if (!last) throw new UaePassConfigurationError("waitUntilDone: no result received");
    return last;
  }

  /** Step 5 — fetch the signed PDF as bytes. Typed-error-mapping consistent with the rest of the SDK. */
  async fetchSignedDocument(documentId: string): Promise<Uint8Array> {
    if (typeof documentId !== "string" || documentId.length === 0) {
      throw new UaePassConfigurationError("`documentId` is required.");
    }
    const token = await this.getToken();
    const http = new HttpClient(
      this.endpoints.signedDocument(documentId),
      this.tokenHttp.fetchFn,
    );
    try {
      return await http.requestBytes({
        method: "GET",
        bearer: token.access_token,
      });
    } catch (err) {
      // 401 — signing token rejected, force a refresh on next call.
      if (
        err instanceof UaePassConfigurationError === false &&
        err &&
        typeof err === "object" &&
        "status" in err &&
        (err as { status?: number }).status === 401
      ) {
        this.invalidateToken();
      }
      throw err;
    }
  }

  /** Step 6 — cleanup. */
  async deleteProcess(processId: string): Promise<void> {
    if (typeof processId !== "string" || processId.length === 0) {
      throw new UaePassConfigurationError("`processId` is required.");
    }
    const token = await this.getToken();
    const http = new HttpClient(
      this.endpoints.deleteSignerProcess(processId),
      this.tokenHttp.fetchFn,
    );
    await http.request<undefined>({
      method: "DELETE",
      bearer: token.access_token,
    });
  }

  // ─────────── internals ───────────

  private static assertString(
    value: string | undefined,
    name: string,
  ): asserts value is string {
    if (typeof value !== "string" || value.length === 0) {
      throw new UaePassConfigurationError(
        `SignatureClient: \`${name}\` is required and must be a non-empty string.`,
      );
    }
  }

  private static validateInterval(ms: number): number {
    if (!Number.isFinite(ms) || ms < 100) {
      throw new UaePassConfigurationError(
        "`intervalMs` must be a finite number ≥ 100ms.",
      );
    }
    return ms;
  }

  private static validateTimeout(ms: number): number {
    if (!Number.isFinite(ms) || ms <= 0) {
      throw new UaePassConfigurationError(
        "`timeoutMs` must be a finite number > 0.",
      );
    }
    return ms;
  }
}

// ─────────── module helpers ───────────

function normaliseDocument(
  document: SignatureSignerProcessRequest["document"],
): { content: string; name: string } {
  if (typeof document === "string") {
    return { content: document, name: "document.pdf" };
  }
  if (!document || typeof document.content !== "string" || document.content.length === 0) {
    throw new UaePassConfigurationError(
      "`document.content` must be a non-empty base64 string.",
    );
  }
  if (typeof document.name !== "string" || document.name.length === 0) {
    throw new UaePassConfigurationError(
      "`document.name` must be a non-empty string (e.g. `\"contract.pdf\"`).",
    );
  }
  return document;
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (signal) {
      const onAbort = () => {
        clearTimeout(t);
        resolve();
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

function defaultFetch() {
  const f = (globalThis as { fetch?: FetchFn }).fetch;
  if (typeof f !== "function") {
    throw new UaePassConfigurationError(
      "No `fetch` implementation found in this runtime.",
    );
  }
  return f;
}
