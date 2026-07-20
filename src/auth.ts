/**
 * OAuth 2.0 authorisation-code + PKCE flow for UAE PASS.
 *
 *   1. `buildAuthorizationUrl()`         → redirect the user to UAE PASS
 *   2. UAE PASS calls the SP's `redirect_uri` with `?code&state`
 *   3. `exchangeCodeForToken(code, …)`   → access + refresh token
 *   4. `getUserInfo(accessToken)`        → profile
 *
 * Designed to be portable — no framework imports. Works in:
 *
 *   - Node 18+ (server or CLI)
 *   - Bun 1+ / Deno 1+
 *   - Modern browsers / SPAs (via `@uaepass/sdk-ts/browser`)
 *   - React Native (with `react-native-get-random-values` polyfill)
 *
 * References:
 *   - https://docs.uaepass.ae/feature-guides/authentication/web-application
 *   - RFC 6749 "The OAuth 2.0 Authorization Framework"
 *   - RFC 7636 "Proof Key for Code Exchange (PKCE)"
 */

import {
  HttpClient,
  basicAuthHeader,
  toFormParams,
  type FetchFn,
} from "./http.js";
import {
  createPkcePair,
  randomUrlSafe,
  safeStringEqual,
  sha256,
  base64UrlEncode,
} from "./crypto.js";
import {
  resolveEndpoints,
  type UaePassEndpoints,
  type Environment,
} from "./endpoints.js";
import {
  UaePassConfigurationError,
  UaePassError,
  UaePassStateError,
} from "./errors.js";
import type {
  AccessTokenResponse,
  Acr,
  Scope,
  UaePassProfile,
} from "./types.js";

export interface UaePassClientConfig {
  /** `"staging"` or `"production"`. Defaults to `"staging"`. */
  environment?: Environment;
  /** OAuth `client_id` from the UAE PASS self-care portal. */
  clientId: string;
  /** OAuth `client_secret` (empty string for public-client PKCE). */
  clientSecret: string;
  /** Registered `redirect_uri` — must match the portal exactly. */
  redirectUri: string;
  /** Override fetch for tests or alternate runtimes. Defaults to global `fetch`. */
  fetch?: FetchFn;
  /** Override endpoints (private cloud / mirror deployments). */
  endpoints?: UaePassEndpoints;
}

export interface AuthorizationRequestInit {
  /** Space-separated list of scopes. Defaults to `urn:uae:digitalid:profile:general`. */
  scope?: Scope[] | string;
  /** Authentication Context Class Reference. */
  acrValues?: Acr | Acr[];
  /** UI locale: `en` or `ar`. */
  uiLocales?: "en" | "ar";
  /** CSRF nonce — must equal `state` returned on callback. Auto-generated if omitted. */
  state?: string;
  /**
   * Supply your own PKCE verifier (43–128 URL-safe chars). When
   * supplied, the matching `code_challenge` is computed automatically —
   * we **never** generate two independent PKCE pairs in one flow.
   */
  codeVerifier?: string;
}

export interface AuthorizationRequestResult {
  /** Absolute URL to redirect the user to. */
  url: string;
  /** State — store this and verify on callback. */
  state: string;
  /** PKCE code_verifier — store alongside state until callback. */
  codeVerifier: string;
}

/** Result returned by `completeLogin()` — what most apps actually need. */
export interface CompletedLogin {
  /** Token to send as `Authorization: Bearer …`. */
  accessToken: string;
  /** Refresh token, if the provider returned one. */
  refreshToken?: string;
  /** Absolute expiry timestamp. */
  expiresAt: Date;
  /** Space-separated scope string the provider granted. */
  scope: string;
  /** Resolved user profile (citizen or visitor). */
  profile: UaePassProfile;
}

/**
 * OAuth + signature client for UAE PASS.
 *
 * Single shared `HttpClient` covers all OAuth endpoints, so the
 * fetch override you supply at construction time propagates to
 * every method (token, userinfo, logout, signature).
 */
export class UaePassClient {
  /** Public for inspection; do not mutate. */
  readonly endpoints: UaePassEndpoints;
  private readonly tokenHttp: HttpClient;
  private readonly userinfoHttp: HttpClient;
  private readonly logoutHttp: HttpClient;
  private readonly signHttp: HttpClient;
  private readonly fetcher: FetchFn;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;

  constructor(config: UaePassClientConfig) {
    UaePassClient.assertString(config.clientId, "clientId");
    UaePassClient.assertString(config.clientSecret, "clientSecret");
    UaePassClient.assertString(config.redirectUri, "redirectUri");

    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.endpoints =
      config.endpoints ??
      resolveEndpoints(config.environment ?? "staging");
    this.fetcher = config.fetch ?? defaultFetch();
    this.tokenHttp = new HttpClient(this.endpoints.token, this.fetcher);
    this.userinfoHttp = new HttpClient(this.endpoints.userinfo, this.fetcher);
    this.logoutHttp = new HttpClient(this.endpoints.logout, this.fetcher);
    this.signHttp = new HttpClient(this.endpoints.signerProcesses, this.fetcher);
  }

  /**
   * Build the absolute /idshub/authorize URL and return the matching
   * state + code-verifier pair. EXACTLY ONE PKCE pair is generated
   * per call — if you supply `init.codeVerifier`, we derive the
   * challenge from it; if you don't, we generate one pair and use
   * BOTH halves together. This guarantees the verifier the server
   * binds to is the same one you store for the callback.
   */
  async buildAuthorizationUrl(
    init: AuthorizationRequestInit = {},
  ): Promise<AuthorizationRequestResult> {
    const state = init.state ?? randomUrlSafe(24);

    // ONE PKCE pair — never two.
    let codeVerifier: string;
    let codeChallenge: string;
    if (init.codeVerifier !== undefined) {
      codeVerifier = init.codeVerifier;
      const digest = await sha256(codeVerifier);
      codeChallenge = base64UrlEncode(digest);
    } else {
      const pair = await createPkcePair();
      codeVerifier = pair.codeVerifier;
      codeChallenge = pair.codeChallenge;
    }

    if (codeVerifier.length < 43 || codeVerifier.length > 128) {
      throw new UaePassConfigurationError(
        "PKCE code-verifier must be 43–128 characters (RFC 7636).",
      );
    }

    const scope = Array.isArray(init.scope)
      ? init.scope.join(" ")
      : init.scope ?? "urn:uae:digitalid:profile:general";

    const acr = Array.isArray(init.acrValues)
      ? init.acrValues.join(" ")
      : init.acrValues ?? "urn:safelayer:tws:policies:authentication:level:low";

    const params: Record<string, string> = {
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope,
      state,
      acr_values: acr,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    };
    if (init.uiLocales) params["ui_locales"] = init.uiLocales;

    const usp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) usp.set(k, v);
    return {
      url: `${this.endpoints.authorize}?${usp.toString()}`,
      state,
      codeVerifier,
    };
  }

  /**
   * Exchange authorisation `code` for an access token. Pass
   * `multipart: true` if your deployment rejects the standard
   * url-encoded body (rare — UAE PASS docs show multipart).
   */
  async exchangeCodeForToken(args: {
    code: string;
    codeVerifier: string;
    /** Override the `redirect_uri` (must match /authorize). */
    redirectUri?: string;
    /** Force `multipart/form-data`. Defaults to `application/x-www-form-urlencoded`. */
    multipart?: boolean;
    signal?: AbortSignal;
  }): Promise<AccessTokenResponse> {
    if (typeof args.code !== "string" || args.code.length === 0) {
      throw new UaePassConfigurationError("`code` is required.");
    }
    if (typeof args.codeVerifier !== "string" || args.codeVerifier.length === 0) {
      throw new UaePassConfigurationError("`codeVerifier` is required.");
    }

    const fields = {
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: args.redirectUri ?? this.redirectUri,
    } as const;

    const basic = basicAuthHeader(this.clientId, this.clientSecret);

    if (args.multipart) {
      // Single multipart POST — no duplicate calls.
      return this.tokenHttp.postMultipart<AccessTokenResponse>(
        { ...fields },
        { signal: args.signal, basicAuth: basic },
      );
    }
    const usp = toFormParams(fields);
    return this.tokenHttp.request<AccessTokenResponse>({
      method: "POST",
      signal: args.signal,
      formBody: usp,
      basicAuth: basic,
    });
  }

  /** Fetch the authenticated user's profile. */
  async getUserInfo(
    accessToken: string,
    opts: { signal?: AbortSignal } = {},
  ): Promise<UaePassProfile> {
    if (typeof accessToken !== "string" || accessToken.length === 0) {
      throw new UaePassConfigurationError("`accessToken` is required.");
    }
    return this.userinfoHttp.request<UaePassProfile>({
      method: "GET",
      signal: opts.signal,
      bearer: accessToken,
    });
  }

  /**
   * One-call helper for the OAuth callback handler:
   *
   *   1. CSRF state check
   *   2. code → tokens
   *   3. access token → userinfo
   *
   * Apps are responsible for storing `{state, codeVerifier}` between
   * their `/login` and `/callback` handlers — pass them back here.
   */
  async completeLogin(args: {
    code: string;
    state: string;
    storedState: string;
    storedVerifier: string;
    signal?: AbortSignal;
  }): Promise<CompletedLogin> {
    this.verifyState(args.storedState, args.state);
    const tokens = await this.exchangeCodeForToken({
      code: args.code,
      codeVerifier: args.storedVerifier,
      signal: args.signal,
    });
    const profile = await this.getUserInfo(tokens.access_token, {
      signal: args.signal,
    });
    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000);
    return {
      accessToken: tokens.access_token,
      ...(tokens.refresh_token !== undefined
        ? { refreshToken: tokens.refresh_token }
        : {}),
      expiresAt,
      scope: tokens.scope,
      profile,
    };
  }

  /** Build a logout URL (RP-initiated). UAE PASS doesn't standardise revoke. */
  buildLogoutUrl(args: {
    postLogoutRedirectUri?: string;
    idTokenHint?: string;
    state?: string;
  } = {}): string {
    const params = new URLSearchParams();
    if (args.postLogoutRedirectUri)
      params.set("post_logout_redirect_uri", args.postLogoutRedirectUri);
    if (args.idTokenHint) params.set("id_token_hint", args.idTokenHint);
    if (args.state) params.set("state", args.state);
    const qs = params.toString();
    return qs ? `${this.endpoints.logout}?${qs}` : this.endpoints.logout;
  }

  /** CSRF: compare stored state with callback `state`. */
  verifyState(stored: string, received: string): void {
    if (!safeStringEqual(stored, received)) throw new UaePassStateError();
  }

  /** Endpoints object — for advanced callers (e.g. the signature client). */
  getEndpoints(): UaePassEndpoints {
    return this.endpoints;
  }

  private static assertString(
    value: string | undefined,
    name: string,
  ): asserts value is string {
    if (typeof value !== "string" || value.length === 0) {
      throw new UaePassConfigurationError(
        `UaePassClient: \`${name}\` is required and must be a non-empty string.`,
      );
    }
  }
}

/** Public alias. */
export const UaePass = UaePassClient;

function defaultFetch(): FetchFn {
  // universal — Node 18+, Bun, Deno, modern browsers all have global fetch.
  const f = (globalThis as { fetch?: FetchFn }).fetch;
  if (typeof f !== "function") {
    throw new UaePassError(
      "configuration_error",
      "No `fetch` implementation found in this runtime. Pass `fetch` explicitly " +
        "to `new UaePassClient({ fetch })` (Node < 18).",
    );
  }
  return f;
}
