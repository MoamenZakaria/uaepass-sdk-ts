/**
 * Public SDK types — the surface every consumer of the library sees.
 *
 * The UAE PASS `idshub` userinfo payload varies by profile:
 *
 *   - Citizen / Resident  → full fields below including `idn`, `idType`
 *   - Visitor            → uses `profileType`, `unifiedID`; no `idn`
 *
 * Both inherit `sub`, `uuid` / `spuuid`, `userType`, and `email`.
 */

export type UserType = "SOP1" | "SOP2" | "SOP3";

/**
 * SOP1 = basic unverified
 * SOP2 = smart-pass / Dubai ID verified (advanced signature only if enabled)
 * SOP3 = fully verified (qualified signature allowed for signing flows)
 */
export interface UaePassBaseProfile {
  /** OIDC subject — stable, opaque. */
  sub: string;
  /** Internal UAE PASS UUID. */
  uuid?: string;
  /** Service-provider scoped UUID (only when `spuuid` is provisioned). */
  spuuid?: string;
  /** Account type — gates which signature flows the user is permitted to perform. */
  userType: UserType;
  email?: string;
}

/**
 * Citizen/Resident profile. UAE PASS always returns these fields when the
 * `urn:uae:digitalid:profile:general` scope is approved — so we model
 * them as required and let integrators narrow their own contract.
 */
export interface UaePassCitizenProfile extends UaePassBaseProfile {
  /** Emirates ID number (required for verified citizen/resident accounts). */
  idn: string;
  /** Document type — typically `"ID"` for Emirates ID. */
  idType: string;
  firstnameEN: string;
  lastnameEN: string;
  fullnameEN: string;
  firstnameAR: string;
  lastnameAR: string;
  fullnameAR: string;
  gender: string;
  mobile: string;
  nationalityEN: string;
  nationalityAR: string;
  /** Authentication Context Class Reference satisfied at login time. */
  acr?: string;
  /** Authentication Methods References (array of URN strings). */
  amr?: readonly string[];
  titleEN?: string;
  titleAR?: string;
}

/**
 * Visitor profile — returned when the visitor-specific scopes
 * (`...:profileType`, `...:unifiedId`) were requested at /authorize.
 */
export interface UaePassVisitorProfile extends UaePassBaseProfile {
  profileType: string;
  unifiedID: string;
  firstnameEN: string;
  lastnameEN: string;
  fullnameEN: string;
  firstnameAR: string;
  lastnameAR: string;
  fullnameAR: string;
  mobile: string;
  nationalityEN: string;
  nationalityAR: string;
  titleEN?: string;
  titleAR?: string;
  gender?: string;
}

/** Union returned by `getUserInfo()`. */
export type UaePassProfile = UaePassCitizenProfile | UaePassVisitorProfile;

/**
 * Narrowing helper — `profile.idn` is the easiest citizen indicator.
 */
export function isCitizen(
  p: UaePassProfile,
): p is UaePassCitizenProfile {
  return "idn" in p && typeof (p as { idn?: unknown }).idn === "string";
}

/** Narrowing helper for visitor profiles. */
export function isVisitor(
  p: UaePassProfile,
): p is UaePassVisitorProfile {
  return "unifiedID" in p && typeof (p as { unifiedID?: unknown }).unifiedID === "string";
}

export interface AccessTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

export interface AccessTokenError {
  error: string;
  error_description?: string;
}

export type Acr =
  | "urn:safelayer:tws:policies:authentication:level:low"
  | "urn:safelayer:tws:policies:authentication:level:substantial"
  | "urn:safelayer:tws:policies:authentication:level:high"
  | "urn:digitalid:authentication:flow:mobileondevice"
  | `urn:uae:digitalid:authentication:flow:ekyc:${"1" | "2"}`;

export type Scope =
  /** Default profile scope (first/last name, email, mobile, nationality, gender). */
  | "urn:uae:digitalid:profile:general"
  /** Visitor identifier (profileType). */
  | "urn:uae:digitalid:profile:general:profileType"
  /** Visitor identifier (unifiedId). */
  | "urn:uae:digitalid:profile:general:unifiedId";

/** Scope required for digital-signature operations. */
export const SIGNATURE_SCOPE = "urn:uae:digitalid:signature";

export interface SignatureSigningAccessToken {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope?: string;
}

/**
 * Input to `createSignerProcess`.
 *
 * `document` may be the raw base64 string OR the `{content, name}` shape.
 * The SDK infers a default `name` of `document.pdf` when a string is passed.
 */
export interface SignatureSignerProcessRequest {
  document: { content: string; name: string } | string;
  description?: string;
  reason?: string;
  hashAlgorithm?: "SHA256" | "SHA512";
  /** Pre-acquired user access token (must include `signature` capability). */
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
 * A small abstraction for persisting login state across the OAuth callback.
 *
 * Generic over the underlying request/response types so the same interface
 * works in Express (`Request`/`Response`), H3 (`H3Event`), Fastify
 * (`FastifyRequest`/`FastifyReply`), or any user-supplied store.
 *
 * The default `cookieSessionStore` returns an `ExpressSessionStore`.
 */
export interface UaePassSessionStore<Req = unknown, Res = unknown> {
  /** Read the persisted state + verifier for the current request, or null. */
  load(req: Req): { state: string; verifier: string } | null;
  /** Persist state + verifier for the next callback. */
  save(res: Res, payload: { state: string; verifier: string }): void;
  /** Clear the persisted state once consumed. */
  clear(res: Res): void;
}

