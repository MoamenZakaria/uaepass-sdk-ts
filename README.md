# @uaepass/sdk-ts

[![npm](https://img.shields.io/npm/v/@uaepass/sdk-ts)](https://www.npmjs.com/package/@uaepass/sdk-ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](#)

> TypeScript SDK for [UAE PASS](https://uaepass.ae) — OAuth 2.0 authentication
> and digital-signature flows, zero runtime deps, works in Node 18+, Bun, Deno,
> browsers, and React Native.

- 🔐 **Authentication** — Authorization Code + PKCE, citizen & visitor profiles
- ✍️ **Digital Signature** — full 6-step trustedx-resources flow
- 🪶 **Zero runtime deps** — Web Crypto + fetch only
- 🧩 **Framework-agnostic core** — Express helper available, H3/Fastify ready
- 🛠 **Typed errors** — `UaePassStateError`, `UaePassOAuthError`, etc.

---

## Why?

UAE PASS publishes documentation at [docs.uaepass.ae](https://docs.uaepass.ae)
but every integrator ends up rewriting the same OAuth + PKCE + signature
plumbing. This SDK gives you a single import that works in:

| Runtime | Status |
|---|---|
| Node 18+ | ✅ tested |
| Bun 1.0+ | ✅ compatible (uses global `fetch` + `crypto`) |
| Deno 1.36+ | ✅ compatible (`--unstable-bytes` not needed) |
| Browsers / React Native | ✅ compatible — `Buffer` calls are gated |

---

## 1. Install

```bash
npm install @uaepass/sdk-ts
```

Add the SDK credentials to your `.env` (sandbox values from the docs):

```env
UAE_PASS_ENV=staging
UAE_PASS_CLIENT_ID=sandbox_stage
UAE_PASS_CLIENT_SECRET=sandbox_stage
UAE_PASS_REDIRECT_URI=http://localhost:3000/callback
```

---

## 2. Five-minute integration

### Server-side (Express, Fastify, H3, …)

The cleanest path. SDK does OAuth + PKCE + state persistence in a signed cookie
— no session middleware needed.

```ts
import express from "express";
import cookieParser from "cookie-parser";
import { UaePass } from "@uaepass/sdk-ts";

const app = express();
app.use(cookieParser());

const up = UaePass.fromEnv();   // reads the 4 UAE_PASS_* env vars

app.use(
  up.expressRouter({
    onLogin: async (req, res, { profile, tokens }) => {
      // `tokens.access_token` is your session. Persist `profile` to your DB.
      req.session.userId = profile.sub;
      req.session.accessToken = tokens.access_token;
    },
    successRedirect: "/dashboard",
    failureRedirect: "/login?error=uaepass",
  }),
);

app.listen(3000);
```

Get credentials in the [Self-Care Portal](https://uaepass.ae) → Developers →
register your app → copy the `client_id` / `client_secret` and match the
`redirect_uri` **exactly** to what you put in the dev portal.

### Mobile (iOS / Android deep-link)

UAE PASS exposes an app-to-app flow when the user has the UAE PASS app
installed (see the [Mobile Integration Guide](https://docs.uaepass.ae/feature-guides/authentication/mobile-application/guide/api)).
The SDK builds the launch URL and handles the redirect's `code`:

```ts
import { UaePassClient } from "@uaepass/sdk-ts";

const up = new UaePassClient({
  environment: "production",
  clientId: "mobile-client-id",
  clientSecret: "mobile-client-secret",
  redirectUri: "myapp://callback",     // matches your Info.plist / deep-link
});

const { url } = await up.buildAuthorizationUrl({
  // On-device flow when the UAE PASS app is installed:
  acrValues: "urn:digitalid:authentication:flow:mobileondevice",
  scope: ["urn:uae:digitalid:profile:general"],
});

// `url` → open in app, or copy into a WebView for fallback.
// Later, on redirect:
const result = await up.completeLogin({
  code:        "received-from-url",
  state:       "received-from-url",
  storedState:        previouslyStoredState,
  storedVerifier:     previouslyStoredVerifier,
});
```

### Browser SPA (no server)

If you're a SPA with no backend, do the token exchange from a thin backend or
proxy endpoint (you cannot expose `client_secret` to the browser).

---

## 3. Digital signature

The full single-document signing flow:

```ts
import { SignatureClient } from "@uaepass/sdk-ts";

const sig = new SignatureClient({
  environment: "production",
  clientId, clientSecret,
});

// 2. Get signing-platform token (client_credentials grant).
await sig.getToken();

// 3. Kick off the signing process.
const { signerProcessId, documentId } = await sig.createSignerProcess({
  document: { content: base64Pdf, name: "contract.pdf" },
  userAccessToken,         // token from /idshub/token, must include signature scope
  description: "Sign at your convenience",
  reason: "approval",
});

// 4. Poll until terminal.
const result = await sig.waitUntilDone(signerProcessId, {
  intervalMs: 2_000,
  timeoutMs:  5 * 60_000,
});

// 5. Download the signed PDF.
if (result.status === "COMPLETED") {
  for (const { id } of result.signedDocuments ?? []) {
    const pdf = await sig.fetchSignedDocument(id);
    await fs.promises.writeFile(`signed-${id}.pdf`, pdf);
  }
}

// 6. Cleanup.
await sig.deleteProcess(signerProcessId);
```

---

## 4. Error handling

All errors extend `UaePassError` so you can branch on `instanceof`:

```ts
import {
  UaePassError,
  UaePassOAuthError,
  UaePassNetworkError,
  UaePassStateError,
  UaePassHttpError,
} from "@uaepass/sdk-ts";

try {
  await up.exchangeCodeForToken({ code, codeVerifier });
} catch (err) {
  if (err instanceof UaePassOAuthError) {
    console.warn("OAuth rejected:", err.code, err.description);
  } else if (err instanceof UaePassStateError) {
    console.warn("Possible CSRF — state mismatch");
  } else if (err instanceof UaePassNetworkError) {
    console.warn("Network blip — retry?");
  } else if (err instanceof UaePassHttpError) {
    console.error("UAE PASS answered", err.status, err.bodyText);
  } else if (err instanceof UaePassError) {
    console.error("Other SDK error", err.code);
  } else throw err;
}
```

---

## 5. API reference

### `UaePassClient` / `UaePass`

| Method | Purpose |
|---|---|
| `UaePass.fromEnv()` | Factory — reads `UAE_PASS_*` env vars |
| `new UaePassClient(cfg)` | Manual construction |
| `buildAuthorizationUrl(init?)` | Build the URL & PKCE pair for /idshub/authorize |
| `exchangeCodeForToken(args)` | `code` → `access_token` (multipart or urlencoded) |
| `getUserInfo(token, opts?)` | Fetch the user's profile (citizen or visitor) |
| `completeLogin(args)` | One-call: verify state + exchange + userinfo |
| `buildLogoutUrl(args?)` | RP-initiated logout URL |
| `verifyState(stored, received)` | Constant-time-safe state check |
| `expressRouter(opts)` | Returns a ready-to-mount Express router |

### `SignatureClient`

| Method | Purpose |
|---|---|
| `getToken(scope?)` | OAuth client_credentials → signing token (cached) |
| `invalidateToken()` | Force-refresh on next call |
| `createSignerProcess(opts)` | Upload the PDF + create the signing process |
| `getResult(processId)` | One-shot status check |
| `waitUntilDone(processId, opts?)` | Polls until `COMPLETED` / `FAILED` / `EXPIRED` |
| `fetchSignedDocument(documentId)` | Stream raw signed PDF as `Uint8Array` |
| `deleteProcess(processId)` | Cleanup the signing process |

### Types

`UaePassCitizenProfile`, `UaePassVisitorProfile`, `UaePassProfile`,
`AccessTokenResponse`, `SignatureSignerProcessResult`, etc. — all exported
and re-exported from the package root.

---

## 6. Configuration reference

### `UaePassClientConfig`

| Field | Type | Default | Notes |
|---|---|---|---|
| `environment` | `"staging" \| "production"` | `"staging"` | |
| `clientId` | `string` | — | |
| `clientSecret` | `string` | — | Use **public-client PKCE** (`clientSecret=""`) if your app is configured as a public client in the Self-Care portal. |
| `redirectUri` | `string` | — | Must match the portal **exactly**. |
| `fetch` | `typeof fetch` | `globalThis.fetch` | Override for tests. |
| `endpoints` | `UaePassEndpoints` | resolved via `environment` | Custom hosts (private-cloud). |

### `SignatureClientConfig`

Same shape, plus:

| Field | Type | Default | Notes |
|---|---|---|---|
| `hashAlgorithm` | `"SHA256" \| "SHA512"` | `"SHA256"` | Per-document hash. |

---

## 7. Scope & ACR reference

| Scope | Use |
|---|---|
| `urn:uae:digitalid:profile:general` | Citizen/Resident: name, email, mobile, gender, nationality |
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

## 8. Running locally

```bash
git clone https://github.com/MoamenZakaria/uaepass-sdk-ts.git
cd uaepass-sdk-ts
npm install
npm test          # vitest run (3 files, 26 tests)
npm run lint      # tsc --noEmit
npm run build     # tsc → dist/
npm run demo      # tsx sample/express-app.ts
```

---

## 9. Roadmap

- [ ] H3 / Nuxt adapter
- [ ] Fastify adapter
- [ ] Multi-document signing flow
- [ ] e-Seal flow
- [ ] Data-sharing authorization flow

---

## 10. License

MIT © 2026 [Moamen Zakaria](https://github.com/MoamenZakaria)
