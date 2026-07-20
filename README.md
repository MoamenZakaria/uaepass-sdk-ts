# `@uaepass/sdk-ts`

> TypeScript SDK for [UAE PASS](https://uaepass.ae) — OAuth 2.0 authentication
> and digital-signature flows, **zero runtime deps**, no framework lock-in.

- 🔐 **Authentication** — Authorization Code + PKCE, citizen & visitor profiles
- ✍️ **Digital signature** — full 6-step trustedx-resources flow
- 🪶 **Zero runtime deps** — Web Crypto + global `fetch` only
- 🧩 **Framework-agnostic core** — works in Express, Fastify, H3, Bun, Deno, browsers, and React Native
- 🛠 **Typed errors** — `UaePassOAuthError`, `UaePassNetworkError`, `UaePassHttpError`, `UaePassStateError`, `UaePassConfigurationError`

---

## Why?

UAE PASS publishes documentation at [docs.uaepass.ae](https://docs.uaepass.ae)
but every integrator ends up rewriting the same OAuth + PKCE + signature plumbing.
This SDK gives you a **single import** that drops into any environment.

| Runtime | Status |
|---|---|
| Node 18+ (server) | ✅ tested, 51 tests pass |
| Bun 1+ | ✅ same as Node (uses global `fetch` + `crypto`) |
| Deno 1.36+ | ✅ same as Node |
| Browsers / SPA | ✅ bundler-friendly, no Buffer/Node imports |
| React Native | ⚠️ requires `react-native-get-random-values` polyfill for `crypto.getRandomValues` |

---

## Install

```bash
npm install @uaepass/sdk-ts
```

Add credentials from the [UAE PASS Self-Care Portal](https://uaepass.ae) →
Developers → register your app:

```env
UAE_PASS_ENV=staging
UAE_PASS_CLIENT_ID=sandbox_stage
UAE_PASS_CLIENT_SECRET=sandbox_stage
UAE_PASS_REDIRECT_URI=http://localhost:3000/callback
```

---

## 5-minute integration (any framework)

### 1. Build the auth URL + store the PKCE pair

```ts
import { UaePassClient } from "@uaepass/sdk-ts";

const up = new UaePassClient({
  environment: "staging",                 // or "production"
  clientId: process.env.UAE_PASS_CLIENT_ID!,
  clientSecret: process.env.UAE_PASS_CLIENT_SECRET!,
  redirectUri: process.env.UAE_PASS_REDIRECT_URI!,
});

// In your "/login" handler — start the round-trip
const { url, state, codeVerifier } = await up.buildAuthorizationUrl();
// → Save `state` + `codeVerifier` somewhere so /callback can find them:
//   cookie (signed), Redis, JWT, DB, anywhere.
// → Redirect the user to `url`.
```

### 2. Complete the login in `/callback`

```ts
// In your "/callback" handler — finish the round-trip
const login = await up.completeLogin({
  code: req.query.code as string,
  state: req.query.state as string,
  storedState:    previouslySavedState,
  storedVerifier: previouslySavedCodeVerifier,
});

// `login` shape:
// {
//   accessToken:    "67f2…",
//   refreshToken?:  "…",
//   expiresAt:      Date,
//   scope:          "urn:uae:digitalid:profile:general",
//   profile:        { sub, uuid, userType, idn, … },
// }
```

> That's the whole OAuth flow. The SDK does **not** pick a framework, a session
> store, or a cookie library — those are yours. If you're on Node, the
> `@uaepass/sdk-ts/node` entry exposes a `fromEnv()` convenience:

```ts
import { fromEnv } from "@uaepass/sdk-ts/node";
const up = fromEnv();
```

### 3. Runnable demo — `node:http` (zero framework)

```bash
cp .env.example .env            # fill in the 4 UAE_PASS_* values
npm run demo                    # tsx examples/node-http-server.ts
# Open http://localhost:3000/login
```

### 4. Framework adapters

Stay tuned — Express, H3, Fastify adapters live as **separate packages**
that depend on this one. Don't bloat your `dependencies` with a framework
just to use this SDK.

---

## Digital signature (single-document flow)

```ts
import { SignatureClient } from "@uaepass/sdk-ts";

const sig = new SignatureClient({
  environment: "production",
  clientId,
  clientSecret,
});

// 1. User authenticates FIRST via /idshub/authorize → `accessToken`
//    with the signature scope (urn:uae:digitalid:signature).
// 2. Get a signing-platform token (client_credentials).
await sig.getToken();

// 3. Kick off the signing process.
const { signerProcessId, documentId } = await sig.createSignerProcess({
  document: { content: base64Pdf, name: "contract.pdf" },
  userAccessToken,                     // token from /idshub/token
  description: "Sign at your convenience",
  reason: "approval",
});

// 4. Poll until terminal (COMPLETED / FAILED / EXPIRED).
const result = await sig.waitUntilDone(signerProcessId, {
  intervalMs: 2_000,
  timeoutMs:  5 * 60_000,
});

// 5. Download the signed PDF.
if (result.status === "COMPLETED") {
  for (const { id } of result.signedDocuments ?? []) {
    const bytes = await sig.fetchSignedDocument(id);
    await fs.promises.writeFile(`signed-${id}.pdf`, bytes);
  }
}

// 6. Cleanup.
await sig.deleteProcess(signerProcessId);
```

---

## Error handling

All errors extend `UaePassError`. Branch on `instanceof`:

```ts
import {
  UaePassError,
  UaePassOAuthError,
  UaePassNetworkError,
  UaePassStateError,
  UaePassHttpError,
  UaePassConfigurationError,
  isUaePassError,
} from "@uaepass/sdk-ts";

try {
  await up.exchangeCodeForToken({ code, codeVerifier });
} catch (err) {
  if (err instanceof UaePassOAuthError) {
    // err.code is one of: invalid_request, invalid_grant, ...
    logger.warn("OAuth rejected", { code: err.code, description: err.description });
  } else if (err instanceof UaePassStateError) {
    logger.warn("CSRF state mismatch");
  } else if (err instanceof UaePassNetworkError) {
    // Retry? Backoff?
  } else if (err instanceof UaePassHttpError) {
    logger.error("Upstream answered", { status: err.status, body: err.bodyText });
  } else if (err instanceof UaePassConfigurationError) {
    // Programming error — fix your config
    throw err;
  } else if (isUaePassError(err)) {
    throw err;
  } else {
    throw err; // unknown — re-throw
  }
}
```

---

## API reference

### `UaePassClient` / `UaePass`

| Method | Returns | Purpose |
|---|---|---|
| `new UaePassClient(cfg)` | client | Manual construction (any runtime) |
| `buildAuthorizationUrl(init?)` | `{ url, state, codeVerifier }` | Build /idshub/authorize URL + PKCE pair |
| `exchangeCodeForToken(args)` | `AccessTokenResponse` | `code` → `access_token` |
| `getUserInfo(token, opts?)` | `UaePassProfile` | Fetch profile (citizen or visitor) |
| `completeLogin(args)` | `{ accessToken, refreshToken?, expiresAt, scope, profile }` | All-in-one: state-verify + token + userinfo |
| `buildLogoutUrl(args?)` | `string` | RP-initiated logout URL |
| `verifyState(stored, received)` | `void` (throws `UaePassStateError` on mismatch) | Constant-time-safe state compare |
| `getEndpoints()` | `UaePassEndpoints` | Resolved URLs for advanced callers |

### `SignatureClient`

| Method | Returns | Purpose |
|---|---|---|
| `getToken(scope?)` | `SignatureSigningAccessToken` | Signing-platform token (cached by `expires_in`) |
| `invalidateToken()` | `void` | Force-refresh on next call |
| `createSignerProcess(opts)` | `{ documentId, signerProcessId }` | Upload the PDF + create the signing process |
| `getResult(processId)` | `SignatureSignerProcessResult` | One-shot status check |
| `waitUntilDone(processId, opts?)` | `SignatureSignerProcessResult` | Polls until `COMPLETED` / `FAILED` / `EXPIRED` |
| `fetchSignedDocument(documentId)` | `Uint8Array` | Raw signed PDF as bytes |
| `deleteProcess(processId)` | `void` | Clean up the signing process |

### Types

`UaePassCitizenProfile`, `UaePassVisitorProfile`, `UaePassProfile`,
`AccessTokenResponse`, `SignatureSignerProcessResult`, `UaePassSessionStore<Req,Res>`,
`HttpClient`, `FetchFn`, etc. — all exported from the package root.

### Identity helpers

- `isCitizen(profile)` — type guard narrowing to `UaePassCitizenProfile`
- `isVisitor(profile)` — type guard narrowing to `UaePassVisitorProfile`
- `isUaePassError(err)` — type guard narrowing to `UaePassError`

---

## Configuration

### `UaePassClientConfig`

| Field | Type | Default | Notes |
|---|---|---|---|
| `environment` | `"staging" \| "production"` | `"staging"` | Endpoint host selection |
| `clientId` | `string` | — | From the Self-Care Portal |
| `clientSecret` | `string` | — | Use **empty string** for public-client PKCE |
| `redirectUri` | `string` | — | Must match the portal exactly |
| `fetch` | `FetchFn` | `globalThis.fetch` | Override for tests / non-standard runtimes |
| `endpoints` | `UaePassEndpoints` | resolved via `environment` | Private cloud / mirror deployments |

### `SignatureClientConfig`

Same shape, plus:

| Field | Type | Default | Notes |
|---|---|---|---|
| `hashAlgorithm` | `"SHA256" \| "SHA512"` | `"SHA256"` | Per-document hash |
| `expirySafetyMs` | `number` | `60_000` | Refresh the signing token this many ms **before** `expires_in` |

---

## Scope & ACR reference

| Scope | Use |
|---|---|
| `urn:uae:digitalid:profile:general` | Citizen/Resident: name, email, mobile, nationality, gender |
| `urn:uae:digitalid:profile:general:profileType` | Visitor: profile type |
| `urn:uae:digitalid:profile:general:unifiedId` | Visitor: unified ID |
| `urn:uae:digitalid:signature` | Required for digital-signature operations |

| ACR | Effect |
|---|---|
| `urn:safelayer:tws:policies:authentication:level:low` | Default — push to user's app |
| `urn:safelayer:tws:policies:authentication:level:substantial` | OTP + PIN |
| `urn:safelayer:tws:policies:authentication:level:high` | Biometric / face match |
| `urn:digitalid:authentication:flow:mobileondevice` | Mobile app-to-app (with UAE PASS app installed) |

---

## Develop locally

```bash
git clone https://github.com/MoamenZakaria/uaepass-sdk-ts.git
cd uaepass-sdk-ts
npm install
npm test          # 51 tests, vitest run
npm run lint      # tsc --noEmit
npm run build     # tsc → dist/
npm run demo      # tsx examples/node-http-server.ts
```

---

## Roadmap

- [ ] H3 / Nuxt adapter (separate package)
- [ ] Fastify adapter (separate package)
- [ ] Multi-document signing flow
- [ ] e-Seal flow
- [ ] Data-sharing authorization flow

---

## License

MIT © 2026 [Moamen Zakaria](https://github.com/MoamenZakaria)
