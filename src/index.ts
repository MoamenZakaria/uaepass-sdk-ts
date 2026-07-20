/**
 * `@uaepass/sdk-ts` — public entry point.
 *
 * Re-exports the OAuth client, signature client, endpoint resolver,
 * error hierarchy, types, and crypto helpers. **No framework imports**;
 * the SDK is portable across Node, Bun, Deno, browsers, and React Native.
 *
 * Node-specific convenience (`UaePass.fromEnv`) lives in `@uaepass/sdk-ts/node`
 * to keep the browser bundle small.
 */

export { UaePassClient as UaePass, UaePassClient } from "./auth.js";
export type {
  UaePassClientConfig,
  AuthorizationRequestInit,
  AuthorizationRequestResult,
  CompletedLogin,
} from "./auth.js";

export { SignatureClient } from "./signature.js";
export type {
  SignatureClientConfig,
  CreateSignerProcessOptions,
  WaitOptions,
} from "./signature.js";

export { resolveEndpoints, parseEnvironment } from "./endpoints.js";
export type { Environment, UaePassEndpoints } from "./endpoints.js";

export {
  UaePassError,
  UaePassNetworkError,
  UaePassHttpError,
  UaePassOAuthError,
  UaePassStateError,
  UaePassConfigurationError,
  isUaePassError,
} from "./errors.js";
export type { UaePassErrorCode, UaePassErrorInit } from "./errors.js";

export {
  HttpClient,
  type FetchFn,
  type HttpRequestOptions,
  toFormParams,
  basicAuthHeader,
} from "./http.js";

export type {
  AccessTokenResponse,
  AccessTokenError,
  Acr,
  Scope,
  SignatureSigningAccessToken,
  SignatureSignerProcessRequest,
  SignatureSignerProcessResponse,
  SignatureSignerProcessResult,
  SignerStatus,
  UaePassBaseProfile,
  UaePassCitizenProfile,
  UaePassVisitorProfile,
  UaePassProfile,
  UserType,
  UaePassSessionStore,
} from "./types.js";
export { isCitizen, isVisitor, SIGNATURE_SCOPE } from "./types.js";

export {
  createPkcePair,
  randomUrlSafe,
  base64Encode,
  base64UrlEncode,
  sha256,
  sha256Hex,
  safeStringEqual,
} from "./crypto.js";
