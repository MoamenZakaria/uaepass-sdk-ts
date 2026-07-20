/**
 * UAE PASS digital-signature client.
 *
 * The full single-document flow per docs.uaepass.ae/feature-guides/signature-integration-guide/digital-signature-single-document/signing-guide:
 *
 *   1. The portal authenticates the user via /idshub/authorize FIRST — the user
 *      access token is passed to all signing endpoints.
 *   2. Get a dedicated `trustedx-resources` token via client_credentials.
 *   3. `createSignerProcess({ document, userAccessToken })` → process + document IDs.
 *   4. `getResult(processId)`                    → status + signed URLs.
 *   5. `fetchSignedDocument(documentId)`         → raw PDF bytes.
 *   6. `deleteProcess(processId)`                → cleanup.
 *
 * This client also exposes `checkStatus(processId)` for polling conveniences.
 */

import { HttpClient, basicAuthHeader } from "./http.js";
import { resolveEndpoints, type Environment, type UaePassEndpoints } from "./endpoints.js";
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
  /** Custom fetch (testing). */
  fetch?: typeof fetch;
  endpoints?: UaePassEndpoints;
  /** Default `hashAlgorithm` for `createSignerProcess()`. */
  hashAlgorithm?: SignatureSignerProcessRequest["hashAlgorithm"];
}

export interface CreateSignerProcessOptions
  extends Omit<SignatureSignerProcessRequest, "userAccessToken"> {
  /** If omitted, the access token from `getToken()` is reused. */
  userAccessToken?: string;
}

export class SignatureClient {
  private readonly endpoints: UaePassEndpoints;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly fetchFn: typeof fetch;
  private readonly defaultHashAlgorithm: NonNullable<
    SignatureSignerProcessRequest["hashAlgorithm"]
  >;
  /** Cached signing-platform token (in-memory; safe for serverless-cold-start). */
  private cachedSigningToken: SignatureSigningAccessToken | null = null;

  constructor(config: SignatureClientConfig) {
    if (!config.clientId) throw new Error("SignatureClient: `clientId` is required.");
    if (!config.clientSecret)
      throw new Error("SignatureClient: `clientSecret` is required.");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.fetchFn = config.fetch ?? fetch;
    this.endpoints = config.endpoints ??
      resolveEndpoints(config.environment ?? "staging");
    this.defaultHashAlgorithm = config.hashAlgorithm ?? "SHA256";
  }

  /** Step 2 — obtain an access token for `trustedx-resources` API calls. */
  async getToken(
    scope = "urn:uae:digitalid:signature",
  ): Promise<SignatureSigningAccessToken> {
    const http = new HttpClient(this.endpoints.signingToken, this.fetchFn);
    const usp = new URLSearchParams();
    usp.set("grant_type", "client_credentials");
    usp.set("scope", scope);

    const token = await http.request<SignatureSigningAccessToken>({
      method: "POST",
      formBody: usp,
      basicAuth: basicAuthHeader(this.clientId, this.clientSecret),
    });
    this.cachedSigningToken = token;
    return token;
  }

  /** Forces a token refresh on the next call. */
  invalidateToken(): void {
    this.cachedSigningToken = null;
  }

  private async authHeader(): Promise<string> {
    const tok = this.cachedSigningToken ?? (await this.getToken());
    return `Bearer ${tok.access_token}`;
  }

  /** Step 3 — create a signing process and upload the document. */
  async createSignerProcess(
    opts: CreateSignerProcessOptions,
  ): Promise<SignatureSignerProcessResponse> {
    if (!opts.userAccessToken) {
      throw new Error(
        "SignatureClient.createSignerProcess: `userAccessToken` is required.",
      );
    }
    const document =
      typeof opts.document === "string"
        ? { content: opts.document, name: "document.pdf" }
        : opts.document;

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

    const http = new HttpClient(this.endpoints.signerProcesses, this.fetchFn);
    const res = await http.request<SignatureSignerProcessResponse>({
      method: "POST",
      jsonBody: payload,
      bearer: (await this.authHeader()).replace(/^Bearer\s+/, ""),
    });
    return res;
  }

  /** Step 4 — get the signing status (poll until COMPLETED / FAILED). */
  async getResult(processId: string): Promise<SignatureSignerProcessResult> {
    if (!processId) throw new Error("getResult: `processId` is required.");
    const http = new HttpClient(
      this.endpoints.signerResult(processId),
      this.fetchFn,
    );
    return http.request<SignatureSignerProcessResult>({
      method: "GET",
      bearer: (await this.authHeader()).replace(/^Bearer\s+/, ""),
    });
  }

  /** Wait until the process reaches a terminal state (or `timeoutMs`). */
  async waitUntilDone(
    processId: string,
    options: { intervalMs?: number; timeoutMs?: number } = {},
  ): Promise<SignatureSignerProcessResult> {
    const intervalMs = options.intervalMs ?? 2_000;
    const timeoutMs = options.timeoutMs ?? 5 * 60_000;
    const started = Date.now();
    let last: SignatureSignerProcessResult | undefined;
    while (Date.now() - started < timeoutMs) {
      last = await this.getResult(processId);
      const terminal: SignerStatus[] = ["COMPLETED", "FAILED", "EXPIRED"];
      if (terminal.includes(last.status)) return last;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    if (!last) throw new Error("waitUntilDone: no result received");
    return last;
  }

  /** Step 5 — fetch the signed PDF as bytes. */
  async fetchSignedDocument(documentId: string): Promise<Uint8Array> {
    if (!documentId)
      throw new Error("fetchSignedDocument: `documentId` is required.");
    const http = new HttpClient(
      this.endpoints.signedDocument(documentId),
      this.fetchFn,
    );
    const res = await this.fetchFn(this.endpoints.signedDocument(documentId), {
      method: "GET",
      headers: {
        Authorization: await this.authHeader(),
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `Failed to fetch signed document ${documentId}: HTTP ${res.status} — ${text.slice(0, 200)}`,
      );
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    return buf;
  }

  /** Step 6 — cleanup. UAE PASS recommends deleting the process when done. */
  async deleteProcess(processId: string): Promise<void> {
    if (!processId) throw new Error("deleteProcess: `processId` is required.");
    const http = new HttpClient(
      this.endpoints.deleteSignerProcess(processId),
      this.fetchFn,
    );
    await http.request<void>({
      method: "DELETE",
      bearer: (await this.authHeader()).replace(/^Bearer\s+/, ""),
    });
  }
}
