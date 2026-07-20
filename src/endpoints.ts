/**
 * Centralized UAE PASS endpoint resolver.
 *
 * The Self-Care Portal (https://uaepass.ae) and Integration Guide
 * (https://docs.uaepass.ae) publish two distinct environments:
 *
 *   - staging  – `stg-id.uaepass.ae`
 *   - production – `id.uaepass.ae`
 *
 * Each environment exposes two overlapping but **non-identical** APIs:
 *
 *   1. OAuth 2.0 Identity Hub (`idshub`) for authentication, token,
 *      userinfo, and logout.
 *   2. TrustedX Signing (`trustedx-resources` / `trustedx-authserver`)
 *      for digital-signature operations.
 */

export type Environment = "staging" | "production";

import { UaePassConfigurationError } from "./errors.js";

/** Hostname for the desired environment. */
const HOSTS: Record<Environment, string> = {
  staging: "stg-id.uaepass.ae",
  production: "id.uaepass.ae",
};

/** Single source of truth — every other module looks up URLs here. */
export interface UaePassEndpoints {
  /** OAuth 2.0 authorization endpoint (browser redirect). */
  authorize: string;
  /** OAuth 2.0 token endpoint. */
  token: string;
  /** OIDC-style userinfo endpoint. */
  userinfo: string;
  /** RP-initiated logout endpoint. */
  logout: string;
  /** Signing-platform access-token endpoint (trustedx-authserver). */
  signingToken: string;
  /** Create document-signing process. */
  signerProcesses: string;
  /** Resolve `{processId}/result` — signing status + URLs. */
  signerResult: (processId: string) => string;
  /** Resolve `{documentId}/content` — fetch signed document binary. */
  signedDocument: (documentId: string) => string;
  /** Resolve `{processId}` — delete a signing process. */
  deleteSignerProcess: (processId: string) => string;
}

export function resolveEndpoints(env: Environment): UaePassEndpoints {
  const host = HOSTS[env];
  const authBase = `https://${host}/idshub`;
  const sigTokenBase = `https://${host}/trustedx-authserver/oauth/main-as/token`;
  const sigBase = `https://${host}/trustedx-resources/esignsp/v2`;

  return {
    authorize: `${authBase}/authorize`,
    token: `${authBase}/token`,
    userinfo: `${authBase}/userinfo`,
    logout: `${authBase}/logout`,
    signingToken: sigTokenBase,
    signerProcesses: `${sigBase}/signer_processes`,
    signerResult: (processId) =>
      `${sigBase}/signer_processes/${encodeURIComponent(processId)}/result`,
    signedDocument: (documentId) =>
      `${sigBase}/documents/${encodeURIComponent(documentId)}/content`,
    deleteSignerProcess: (processId) =>
      `${sigBase}/signer_processes/${encodeURIComponent(processId)}`,
  };
}

/** Throw if a user-supplied environment string isn't recognized. */
export function parseEnvironment(value: string | undefined): Environment {
  const v = (value ?? "staging").toLowerCase();
  if (v === "staging" || v === "production") return v;
  throw new UaePassConfigurationError(
    `Unknown UAE PASS environment "${value}". Expected "staging" or "production".`,
  );
}
