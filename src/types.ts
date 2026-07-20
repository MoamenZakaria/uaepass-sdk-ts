/**
 * Public SDK types — the surface every consumer of the library sees.
 *
 * The UAE PASS `idshub` userinfo payload varies by profile:
 *
 *   - Citizen/Resident → includes `idn`, `idType`
 *   - Visitor         → includes `profileType`, `unifiedID`
 *
 * Both inherit `sub`, `uuid`/`spuuid`, `userType`, and `email`.
 *
 * Types are **closed unions** for the well-known fields, but every
 * object keeps an index signature `[k: string]: unknown` so newly
 * added provider fields don't break callers.
 */

/** SDK-level SOP account types per UAE PASS docs. */
export type UserType = "SOP1" | "SOP2" | "SOP3";

/** SOP1 unverified · SOP2 smart-pass · SOP3 fully verified. */
export interface UaePassBaseProfile {
  /** OIDC subject — stable, opaque. */
  sub: string;
  /** Internal UAE PASS UUID. */
  uuid?: string;
  /** Service-provider-scoped UUID (only when spuuid is provisioned). */
  spuuid?: string;
  /** Account type — gates which signature flows the user may perform. */
  userType: UserType;
  email?: string;
  /** Catch-all for newly added provider fields. */
  [field: string]: unknown;
}

/**
 * Citizen / Resident profile. The well-known required fields are
 * marked required; everything else is optional. The index signature
 * keeps the type future-proof.
 */
export interface UaePassCitizenProfile extends UaePassBaseProfile {
  /** Emirates ID number. */
  idn?: string;
  /** Document type, e.g. `"ID"`. */
  idType?: string;
  firstnameEN?: string;
  lastnameEN?: string;
  fullnameEN?: string;
  firstnameAR?: string;
  lastnameAR?: string;
  fullnameAR?: string;
  gender?: string;
  mobile?: string;
  nationalityEN?: string;
  nationalityAR?: string;
  titleEN?: string;
  titleAR?: string;
  /** Authentication Context Class Reference satisfied at login. */
  acr?: string;
  /** Authentication Methods References (array of URNs). */
  amr?: readonly string[];
}

/**
 * Visitor profile — returned when the visitor-specific scopes
 * (`...:profileType`, `...:unifiedId`) are requested at /authorize.
 */
export interface UaePassVisitorProfile extends UaePassBaseProfile {
  profileType?: string;
  unifiedID?: string;
  firstnameEN?: string;
  lastnameEN?: string;
  fullnameEN?: string;
  firstnameAR?: string;
  lastnameAR?: string;
  fullnameAR?: string;
  mobile?: string;
  nationalityEN?: string;
  nationalityAR?: string;
  titleEN?: string;
  titleAR?: string;
  gender?: string;
}

/** Union returned by `getUserInfo()`. */
export type UaePassProfile = UaePassCitizenProfile | UaePassVisitorProfile;

/** Narrowing helper — `profile.idn` is the easiest citizen indicator. */
export function isCitizen(p: UaePassProfile): p is UaePassCitizenProfile {
  return typeof (p as { idn?: unknown }).idn === "string";
}

/** Narrowing helper — `profile.unifiedID` is the easiest visitor indicator. */
export function isVisitor(p: UaePassProfile): p is UaePassVisitorProfile {
  return typeof (p as { unifiedID?: unknown }).unifiedID === "string";
}

/** OAuth access-token response (RFC 6749 §5.1). */
export interface AccessTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

/** OAuth error response (RFC 6749 §5.2). */
export interface AccessTokenError {
  error: string;
  error_description?: string;
}

/**
 * Authentication Context Class Reference. Selects the strength of
 * authentication asked of UAE PASS during the /authorize redirect.
 */
export type Acr =
  | "urn:safelayer:tws:policies:authentication:level:low"
  | "urn:safelayer:tws:policies:authentication:level:substantial"
  | "urn:safelayer:tws:policies:authentication:level:high"
  | "urn:digitalid:authentication:flow:mobileondevice"
  | `urn:uae:digitalid:authentication:flow:ekyc:${"1" | "2"}`;

/** OAuth scopes accepted by the SDK; include `SIGNATURE_SCOPE` for the sign flow. */
export type Scope =
  /** Default profile scope (name, email, mobile, nationality, gender). */
  | "urn:uae:digitalid:profile:general"
  /** Visitor identifier (profileType). */
  | "urn:uae:digitalid:profile:general:profileType"
  /** Visitor identifier (unifiedId). */
  | "urn:uae:digitalid:profile:general:unifiedId"
  /** Required for digital-signature operations. */
  | "urn:uae:digitalid:signature";

/** Scope required for digital-signature operations (re-exported const). */
export const SIGNATURE_SCOPE = "urn:uae:digitalid:signature" as const satisfies Scope;

/** TrustedX signing-platform access token. */
export interface SignatureSigningAccessToken {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope?: string;
}

/**
 * Input to `SignatureClient.createSignerProcess`.
 *
 * `document` accepts either a raw base64 string or the `{content, name}`
 * shape. Default `name` is `document.pdf` when a string is passed.
 */
export interface SignatureSignerProcessRequest {
  /** Base64-encoded PDF bytes. */
  document: { content: string; name: string } | string;
  description?: string;
  reason?: string;
  hashAlgorithm?: "SHA256" | "SHA512";
  /** Pre-acquired user access token (must include the signature scope). */
  userAccessToken: string;
}

export interface SignatureSignerProcessResponse {
  /** Document ID issued by UAE PASS. */
  documentId: string;
  /** Signer-process ID. */
  signerProcessId: string;
}

export type SignerStatus =
  | "CREATED"
  | "PENDING"
  | "IN_PROGRESS"
  | "COMPLETED"
  | "FAILED"
  | "EXPIRED";

export interface SignatureSignerProcessResult {
  status: SignerStatus;
  /** URLs to the produced (signed) documents, when status === COMPLETED. */
  signedDocuments?: readonly { id: string; url: string }[];
  /** Failure description if status === FAILED. */
  errorDescription?: string;
  /** Per-signer results (multi-signer flows). */
  signers?: readonly {
    signerId: string;
    status: SignerStatus;
    signedDocumentId?: string;
  }[];
}

/**
 * Generic persistence contract for the OAuth `state` and PKCE verifier.
 *
 * The SDK only needs `{state, codeVerifier}` round-tripped from the
 * /login handler to the /callback handler — apps wire their own
 * storage (cookie, JWT, Redis, DB). The interface is generic over the
 * request/response types so any framework can plug in.
 *
 * @example
 * ```ts
 * // In-memory example — useful for tests
 * const store: UaePassSessionStore = {
 *   let buf;
 *   load: () => buf ?? null,
 *   save: (_, p) => { buf = p; },
 *   clear: () => { buf = null; },
 * };
 * ```
 */
export interface UaePassSessionStore<Req = unknown, Res = unknown> {
  /** Read persisted state + verifier, or null if none is in flight. */
  load(req: Req): { state: string; verifier: string } | null;
  /** Persist state + verifier for the next callback. */
  save(res: Res, payload: { state: string; verifier: string }): void;
  /** Clear persisted state once consumed. */
  clear(res: Res): void;
}
