/**
 * @uaepass/sdk-ts — public entry point.
 *
 * Re-exports the OAuth client, error classes, types, and helpers. The
 * Express adapter is published on a separate export name so it stays
 * optional (no Express import unless the consumer asks for it).
 */

export { UaePassClient as UaePass, UaePassClient } from "./auth.js";
export type {
  UaePassClientConfig,
  AuthorizationRequestInit,
  AuthorizationRequestResult,
  CompletedLogin,
  UaePassEnvConfig,
} from "./auth.js";

export { SignatureClient } from "./signature.js";
export type {
  SignatureClientConfig,
  CreateSignerProcessOptions,
} from "./signature.js";

export {
  resolveEndpoints,
  parseEnvironment,
} from "./endpoints.js";
export type { Environment, UaePassEndpoints } from "./endpoints.js";

export {
  UaePassError,
  UaePassNetworkError,
  UaePassHttpError,
  UaePassOAuthError,
  UaePassStateError,
} from "./errors.js";
export type { UaePassErrorCode } from "./errors.js";

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
} from "./types.js";

export {
  createPkcePair,
  randomUrlSafe,
  base64UrlEncode,
  sha256Hex,
  safeStringEqual,
} from "./crypto.js";
