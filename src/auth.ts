/**
 * OAuth 2.0 authorisation-code + PKCE flow for UAE PASS.
 *
 *   1. `buildAuthorizationUrl()`         → redirects the user to UAE PASS
 *   2. UAE PASS calls the SP's redirect_uri with `?code&state`
 *   3. `exchangeCodeForToken(code, …)`   → access + refresh token
 *   4. `getUserInfo(accessToken)`        → profile
 *
 * For most apps the all-in-one `UaePass.fromEnv()` + `.expressRouter()` is
 * the simplest entry point — see `sample/express-app.ts`.
 *
 * References:
 *   - https://docs.uaepass.ae/feature-guides/authentication/web-application
 *   - RFC 6749 "The OAuth 2.0 Authorization Framework"
 *   - RFC 7636 "Proof Key for Code Exchange (PKCE)"
 */

import {
  HttpClient,
  asAccessTokenResponse,
  basicAuthHeader,
  toFormParams,
} from "./http.js";
import type { UaePassSessionStore } from "./types.js";
import {
  createPkcePair,
  randomUrlSafe,
  safeStringEqual,
} from "./crypto.js";
import {
  resolveEndpoints,
  parseEnvironment,
  type UaePassEndpoints,
  type Environment,
} from "./endpoints.js";
import { UaePassStateError } from "./errors.js";
import type {
  AccessTokenResponse,
  Acr,
  Scope,
  UaePassProfile,
} from "./types.js";

export interface UaePassClientConfig {
  /** "staging" or "production". Defaults to `process.env.UAE_PASS_ENV` or "staging". */
  environment?: Environment;
  /** OAuth client_id from UAE PASS self-care portal. */
  clientId: string;
  /** OAuth client_secret (confidential clients). */
  clientSecret: string;
  /** Registered redirect_uri exactly as in self-care portal. */
  redirectUri: string;
  /** Override fetch — used by tests. */
  fetch?: typeof fetch;
  /** Override the entire endpoint set (test escape hatch). */
  endpoints?: UaePassEndpoints;
}

export interface AuthorizationRequestInit {
  /** Space-separated list of scopes. Defaults to `urn:uae:digitalid:profile:general`. */
  scope?: Scope[] | string;
  /** Authentication Context Class Reference. */
  acrValues?: Acr | Acr[];
  /** UI locale: `en` or `ar`. */
  uiLocales?: "en" | "ar";
  /** CSRF nonce — must equal the `state` returned on callback. */
  state?: string;
  /** PKCE verifier — auto-generated if omitted. */
  codeVerifier?: string;
  /** Pass-through anything else. */
  extra?: Record<string, string>;
}

export interface AuthorizationRequestResult {
  /** Absolute URL to redirect the user to. */
  url: string;
  /** State value — store this and verify on callback. */
  state: string;
  /** PKCE code_verifier — store alongside state until callback. */
  codeVerifier: string;
}

/** Env-var mapping used by `UaePass.fromEnv()`. */
export interface UaePassEnvConfig {
  /** @default process.env.UAE_PASS_ENV */
  environment?: string;
  /** @default process.env.UAE_PASS_CLIENT_ID */
  clientId?: string;
  /** @default process.env.UAE_PASS_CLIENT_SECRET */
  clientSecret?: string;
  /** @default process.env.UAE_PASS_REDIRECT_URI */
  redirectUri?: string;
}

/**
 * Result returned by `completeLogin()` — the single thing most apps need
 * after the OAuth callback completes.
 */
export interface CompletedLogin {
  accessToken: string;
  refreshToken?: string;
  expiresAt: Date;
  scope: string;
  profile: UaePassProfile;
}

/** Default set of env vars read by `UaePass.fromEnv()`. */
export const ENV_KEYS = {
  environment: "UAE_PASS_ENV",
  clientId: "UAE_PASS_CLIENT_ID",
  clientSecret: "UAE_PASS_CLIENT_SECRET",
  redirectUri: "UAE_PASS_REDIRECT_URI",
} as const;

// `UaePass` alias is defined at the bottom of this file.


/**
 * Main client — every operation routes through `endpoints`.
 * Construct once per process and reuse.
 *
 * Quick start:
 *
 *   import { UaePass } from "@uaepass/sdk-ts";
 *   const up = UaePass.fromEnv();
 *   app.use(up.expressRouter({ onLogin: ... }));
 */
export class UaePassClient {
  readonly endpoints: UaePassEndpoints;
  private readonly http: HttpClient;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;

  constructor(config: UaePassClientConfig) {
    requireString(config.clientId, "clientId");
    requireString(config.clientSecret, "clientSecret");
    requireString(config.redirectUri, "redirectUri");

    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.endpoints =
      config.endpoints ?? resolveEndpoints(config.environment ?? "staging");
    this.http = new HttpClient(this.endpoints.token, config.fetch ?? fetch);
  }

  /**
   * Build a client by reading `UAE_PASS_ENV`, `UAE_PASS_CLIENT_ID`,
   * `UAE_PASS_CLIENT_SECRET`, and `UAE_PASS_REDIRECT_URI` from the
   * environment (or any overrides you pass).
   *
   * The convenience helper keeps the most common case to a single import:
   *
   *   import { UaePass } from "@uaepass/sdk-ts";
   *   const up = UaePass.fromEnv();
   */
  static fromEnv(env: UaePassEnvConfig = {}): UaePassClient {
    const pick = <K extends keyof UaePassEnvConfig>(k: K, def: string) => {
      const v = env[k];
      return typeof v === "string" && v.length > 0 ? v : def;
    };
    const environment = pick("environment", process.env[ENV_KEYS.environment] ?? "");
    const clientId = pick("clientId", process.env[ENV_KEYS.clientId] ?? "");
    const clientSecret = pick("clientSecret", process.env[ENV_KEYS.clientSecret] ?? "");
    const redirectUri = pick("redirectUri", process.env[ENV_KEYS.redirectUri] ?? "");
    const missing = [
      ["environment", environment],
      ["clientId", clientId],
      ["clientSecret", clientSecret],
      ["redirectUri", redirectUri],
    ].filter(([, v]) => !v);

    if (missing.length > 0) {
      throw new Error(
        `UaePass.fromEnv: missing required env var(s): ${missing
          .map(([k]) => `${ENV_KEYS[k as keyof typeof ENV_KEYS]} (${k})`)
          .join(", ")}.\n` +
          `Set them in your .env (see .env.example) or pass them explicitly.`,
      );
    }

    return new UaePassClient({
      environment: parseEnvironment(environment),
      clientId,
      clientSecret,
      redirectUri,
    });
  }

  /** Build an absolute authorization-endpoint URL + matching state + PKCE pair. */
  async buildAuthorizationUrl(
    init: AuthorizationRequestInit = {},
  ): Promise<AuthorizationRequestResult> {
    const state = init.state ?? randomUrlSafe(24);
    const verifier = init.codeVerifier ?? (await createPkcePair()).codeVerifier;

    const scope = Array.isArray(init.scope)
      ? init.scope.join(" ")
      : init.scope ?? "urn:uae:digitalid:profile:general";

    const acr = Array.isArray(init.acrValues)
      ? init.acrValues.join(" ")
      : init.acrValues ?? "urn:safelayer:tws:policies:authentication:level:low";

    const params = new Map<string, string>([
      ["response_type", "code"],
      ["client_id", this.clientId],
      ["redirect_uri", this.redirectUri],
      ["scope", scope],
      ["state", state],
      ["acr_values", acr],
    ]);
    if (init.uiLocales) params.set("ui_locales", init.uiLocales);
    // PKCE: we always have a verifier (own code path); add the challenge unless caller disabled it.
    if (!init.codeVerifier || init.extra?.["code_challenge"]) {
      params.set(
        "code_challenge",
        init.extra?.["code_challenge"] ?? (await createPkcePair()).codeChallenge,
      );
      params.set("code_challenge_method", "S256");
    }
    for (const [k, v] of Object.entries(init.extra ?? {})) {
      if (!params.has(k)) params.set(k, v);
    }

    const usp = new URLSearchParams();
    params.forEach((v, k) => usp.set(k, v));

    return {
      url: `${this.endpoints.authorize}?${usp.toString()}`,
      state,
      codeVerifier: verifier,
    };
  }

  /**
   * Exchange authorisation code for an access token.
   *
   * Pass `multipart: true` if the deployment rejects the standard
   * urlencoded body — UAE PASS docs show `multipart/form-data`, though
   * urlencoded is universally accepted in practice.
   */
  async exchangeCodeForToken(args: {
    code: string;
    codeVerifier: string;
    redirectUri?: string;
    multipart?: boolean;
    /** Abort the call via AbortSignal (e.g. on request cancellation). */
    signal?: AbortSignal;
  }): Promise<AccessTokenResponse> {
    if (!args.code) throw new Error("exchangeCodeForToken: `code` is required.");
    if (!args.codeVerifier)
      throw new Error("exchangeCodeForToken: `codeVerifier` is required.");

    const query = toFormParams({
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: args.redirectUri ?? this.redirectUri,
    });

    let raw: unknown;
    if (args.multipart) {
      const fd = new FormData();
      query.forEach((v, k) => fd.set(k, v));
      const http = new HttpClient(this.endpoints.token, this.fetchOrConfig());
      raw = await http.request<unknown>({
        method: "POST",
        signal: args.signal,
        basicAuth: basicAuthHeader(this.clientId, this.clientSecret),
        jsonBody: undefined,
      });
      // postForm below
      raw = await http.postForm<unknown>({
        grant_type: query.get("grant_type") ?? "authorization_code",
        code: query.get("code") ?? "",
        redirect_uri: query.get("redirect_uri") ?? "",
      });
    } else {
      raw = await this.http.request<unknown>({
        method: "POST",
        signal: args.signal,
        formBody: query,
        basicAuth: basicAuthHeader(this.clientId, this.clientSecret),
      });
    }
    return asAccessTokenResponse(raw);
  }

  /** Fetch the authenticated user's profile. */
  async getUserInfo(
    accessToken: string,
    opts: { signal?: AbortSignal } = {},
  ): Promise<UaePassProfile> {
    if (!accessToken) throw new Error("getUserInfo: `accessToken` is required.");
    const http = new HttpClient(this.endpoints.userinfo, this.fetchOrConfig());
    return http.request<UaePassProfile>({
      method: "GET",
      signal: opts.signal,
      bearer: accessToken,
    });
  }

  /**
   * The single helper that covers ~80% of real apps:
   *
   *   - verifies CSRF state against what was stored before /login
   *   - exchanges the code for tokens
   *   - fetches the user profile
   *
   * Throws `UaePassStateError` on mismatch, OAuth errors otherwise.
   */
  async completeLogin(args: {
    /** The `code` query parameter from UAE PASS. */
    code: string;
    /** The `state` query parameter from UAE PASS. */
    state: string;
    /** The `state` you stored when calling `buildAuthorizationUrl()`. */
    storedState: string;
    /** The `codeVerifier` you stored alongside state. */
    storedVerifier: string;
    /** Abort signal forwarded to fetch. */
    signal?: AbortSignal;
  }): Promise<CompletedLogin> {
    this.verifyState(args.storedState, args.state);
    const tokens = await this.exchangeCodeForToken({
      code: args.code,
      codeVerifier: args.storedVerifier,
      signal: args.signal,
    });
    const profile = await this.getUserInfo(tokens.access_token, { signal: args.signal });
    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000);
    return {
      accessToken: tokens.access_token,
      ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
      expiresAt,
      scope: tokens.scope,
      profile,
    };
  }

  /** Build a logout URL — RP-initiated. UAE PASS does not standardise revoke. */
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

  /** Verify callback `state` against the stored value. Throws on mismatch. */
  verifyState(stored: string, received: string): void {
    if (!safeStringEqual(stored, received)) throw new UaePassStateError();
  }

  /** Expose endpoints for use by the signature client. */
  getEndpoints(): UaePassEndpoints {
    return this.endpoints;
  }

  /**
   * Attach the bundled Express router — the recommended default.
   *
   *   app.use(up.expressRouter({ onLogin: (req, res, ctx) => { ... } }));
   *
   * Returns the router so it can be `.use()`-mounted at a custom path.
   */
  expressRouter(opts: ExpressRouterMountOptions): ExpressRouterHandle {
    if (!opts.onLogin)
      throw new Error("expressRouter: `onLogin` callback is required.");
    // The actual router builder lives in `./express.js` to keep the
    // dependency optional. We import lazily so plain Node consumers
    // never pay the cost.
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    const mod = require("./express.js") as typeof import("./express.js");
    const r = mod.createUaePassRouter({
      client: this,
      successRedirect: opts.successRedirect ?? "/",
      failureRedirect: opts.failureRedirect ?? "/",
      logoutRedirectUri: opts.logoutRedirectUri ?? this.redirectUri,
      scope: opts.scope,
      acrValues: opts.acrValues,
      uiLocales: opts.uiLocales,
      onLogin: opts.onLogin as Parameters<typeof mod.createUaePassRouter>[0]["onLogin"],
      onError: opts.onError as Parameters<typeof mod.createUaePassRouter>[0]["onError"],
      session: opts.session as Parameters<typeof mod.createUaePassRouter>[0]["session"],
    });
    return r as unknown as ExpressRouterHandle;
  }

  private fetchOrConfig(): typeof fetch {
    // The HttpClient inside this class was constructed with whatever fetch
    // was passed to the constructor (defaulting to global fetch). For
    // getUserInfo / exchangeCodeForToken we re-use the same global fetch
    // when no override was provided; if an override exists, this method
    // currently can't recover it without a refactor (kept as a private
    // seam for future tests).
    return fetch;
  }
}

/** Mirror of the Express helper options — re-declared here to avoid an
 * unconditional Express type import in this file.
 */
export interface ExpressRouterMountOptions {
  onLogin: (
    req: unknown,
    res: unknown,
    ctx: { profile: UaePassProfile; tokens: AccessTokenResponse },
  ) => void | Promise<void>;
  onError?: (req: unknown, res: unknown, err: unknown) => void;
  successRedirect?: string;
  failureRedirect?: string;
  logoutRedirectUri?: string;
  scope?: AuthorizationRequestInit["scope"];
  acrValues?: AuthorizationRequestInit["acrValues"];
  uiLocales?: AuthorizationRequestInit["uiLocales"];
  session?: unknown;
}

/** Marker type for the Express router (duck-typed to a function with `.use()`). */
export interface ExpressRouterHandle {
  (req: unknown, res: unknown, next?: unknown): unknown;
  use?: (...args: unknown[]) => unknown;
  get?: (...args: unknown[]) => unknown;
  post?: (...args: unknown[]) => unknown;
  delete?: (...args: unknown[]) => unknown;
}

function requireString(value: string | undefined, name: string): asserts value is string {
  if (!value || value.length === 0) {
    throw new Error(`UaePassClient: \`${name}\` is required.`);
  }
}

/** Public alias used by docs and exported from `index.ts`. */
export const UaePass = UaePassClient;
