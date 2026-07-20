/**
 * Unit tests for the OAuth client (`UaePassClient`).
 *
 * The most important test in this file is "PKCE round-trip":
 * a verifier returned by `buildAuthorizationUrl()` must satisfy
 * `exchangeCodeForToken({ codeVerifier: … })`, otherwise login
 * breaks. The previous codebase had this broken (issue #1 of the
 * 2026-07-20 review); this test guards against regression.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  UaePass,
  UaePassClient,
  UaePassClientConfig,
  HttpClient,
  parseEnvironment,
  resolveEndpoints,
  isCitizen,
  isVisitor,
  createPkcePair,
  safeStringEqual,
  randomUrlSafe,
  base64UrlEncode,
  base64Encode,
  sha256Hex,
  UaePassOAuthError,
  UaePassHttpError,
  UaePassNetworkError,
  UaePassConfigurationError,
  UaePassStateError,
  UaePassError,
  isUaePassError,
  asAccessTokenResponse,
} from "../src/index.js";

// ─────────── helpers ───────────

function makeResponse(body: unknown, status = 200, contentType = "application/json"): Response {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  const ct = contentType.toLowerCase().includes("json") ? "application/json" : contentType;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (k: string) => {
        if (k.toLowerCase() === "content-type") return ct;
        return null;
      },
    },
    text: async () => text,
    json: async () => (typeof body === "string" ? JSON.parse(body) : body),
    arrayBuffer: async () => new TextEncoder().encode(text).buffer,
  } as unknown as Response;
}

function fixedFetchMock(
  responses: (request: { url: string; init: RequestInit }) => Response,
): typeof fetch & { mock: ReturnType<typeof vi.fn>["mock"] } {
  const fn = vi.fn(async (url: string | URL, init: RequestInit = {}) =>
    responses({ url: String(url), init }));
  return fn as unknown as typeof fetch & {
    mock: ReturnType<typeof vi.fn>["mock"];
  };
}

const baseCfg: UaePassClientConfig = {
  environment: "staging",
  clientId: "test_client",
  clientSecret: "test_secret",
  redirectUri: "https://test.example/callback",
};

// ─────────── env / endpoints ───────────

describe("parseEnvironment", () => {
  it("defaults to staging", () => {
    expect(parseEnvironment(undefined)).toBe("staging");
  });
  it("accepts production", () => {
    expect(parseEnvironment("production")).toBe("production");
  });
  it("throws UaePassConfigurationError on unknown", () => {
    expect(() => parseEnvironment("bogus")).toThrow(
      UaePassConfigurationError,
    );
  });
});

describe("resolveEndpoints", () => {
  it("staging returns staging hostnames", () => {
    const e = resolveEndpoints("staging");
    expect(e.authorize).toBe("https://stg-id.uaepass.ae/idshub/authorize");
    expect(e.signerProcesses).toContain("/trustedx-resources/esignsp/v2");
  });
  it("production returns production hostnames", () => {
    const e = resolveEndpoints("production");
    expect(e.userinfo).toBe("https://id.uaepass.ae/idshub/userinfo");
  });
  it("parameterised signing URLs interpolate correctly", () => {
    const e = resolveEndpoints("staging");
    expect(e.signerResult("abc/123?x=")).toContain("signer_processes/abc%2F123%3Fx%3D/result");
    expect(e.signedDocument("doc-99")).toContain("documents/doc-99/content");
    expect(e.deleteSignerProcess("p-1")).toContain("signer_processes/p-1");
  });
});

// ─────────── crypto ───────────

describe("createPkcePair", () => {
  it("produces verifier 43–128 chars + S256 challenge", async () => {
    const p = await createPkcePair(64);
    expect(p.codeVerifier.length).toBe(64);
    expect(p.codeChallengeMethod).toBe("S256");
    expect(p.codeChallenge.length).toBeGreaterThanOrEqual(43);
    expect(p.codeChallenge).toMatch(/^[A-Za-z0-9\-_]+$/);
  });
  it("rejects out-of-range integer verifier lengths", async () => {
    await expect(createPkcePair(20)).rejects.toThrow(/integer in \[43, 128\]/);
    await expect(createPkcePair(200)).rejects.toThrow(/integer in \[43, 128\]/);
  });
  it("rejects non-integer verifier lengths (issue from review)", async () => {
    await expect(createPkcePair(64.5)).rejects.toThrow(/integer in \[43, 128\]/);
    await expect(createPkcePair(NaN)).rejects.toThrow(/integer in \[43, 128\]/);
  });
});

describe("crypto base64", () => {
  it("randomUrlSafe produces URL-safe characters only", () => {
    const r = randomUrlSafe(64);
    expect(r).toMatch(/^[A-Za-z0-9\-_]+$/);
  });
  it("base64UrlEncode strips padding and uses URL-safe alphabet", () => {
    const enc = base64UrlEncode("aa?");
    expect(enc).not.toContain("=");
    expect(enc).not.toContain("+");
    expect(enc).not.toContain("/");
  });
  it("base64Encode produces standard base64", () => {
    expect(base64Encode("hello")).toBe("aGVsbG8=");
  });
  it("sha256Hex returns uppercase 64 chars", async () => {
    const h = await sha256Hex("");
    expect(h).toBe(
      "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    );
  });
  it("safeStringEqual matches/mismatches correctly", () => {
    expect(safeStringEqual("a", "a")).toBe(true);
    expect(safeStringEqual("a", "b")).toBe(false);
    expect(safeStringEqual("aa", "a")).toBe(false);
  });
});

// ─────────── buildAuthorizationUrl ───────────

describe("UaePassClient.buildAuthorizationUrl", () => {
  it("emits correct PKCE challenge + state in the URL", async () => {
    const up = new UaePassClient(baseCfg);
    const r = await up.buildAuthorizationUrl();
    const u = new URL(r.url);
    expect(u.origin + u.pathname).toBe(
      "https://stg-id.uaepass.ae/idshub/authorize",
    );
    expect(u.searchParams.get("client_id")).toBe("test_client");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")).toBeTruthy();
    expect(r.state.length).toBeGreaterThan(16);
    expect(r.codeVerifier.length).toBe(64);
  });
  it("visitor scope configuration propagates to the URL", async () => {
    const up = new UaePassClient(baseCfg);
    const r = await up.buildAuthorizationUrl({
      scope: [
        "urn:uae:digitalid:profile:general",
        "urn:uae:digitalid:profile:general:profileType",
        "urn:uae:digitalid:profile:general:unifiedId",
      ],
    });
    expect(new URL(r.url).searchParams.get("scope")).toContain("unifiedId");
  });
  it("uiLocales appear in the URL when set", async () => {
    const up = new UaePassClient(baseCfg);
    const r = await up.buildAuthorizationUrl({ uiLocales: "ar" });
    expect(new URL(r.url).searchParams.get("ui_locales")).toBe("ar");
  });
  it("uses caller-supplied verifier and derives its challenge", async () => {
    const up = new UaePassClient(baseCfg);
    const suppliedVerifier = randomUrlSafe(64);
    const r = await up.buildAuthorizationUrl({ codeVerifier: suppliedVerifier });
    expect(r.codeVerifier).toBe(suppliedVerifier);
    const { sha256 } = await import("../src/crypto.js");
    const expected = base64UrlEncode(await sha256(suppliedVerifier));
    expect(new URL(r.url).searchParams.get("code_challenge")).toBe(expected);
  });

  // The 🔴 issue #1 from review: previously this would have generated
  // a DIFFERENT verifier for the challenge than the one returned to the
  // caller, breaking OAuth round-trip.
  it("PKCE round-trip: returned verifier matches the challenge sent to the server", async () => {
    const up = new UaePassClient(baseCfg);
    const r = await up.buildAuthorizationUrl();
    const { sha256, base64UrlEncode } = await import("../src/crypto.js");
    const expectedChallenge = base64UrlEncode(await sha256(r.codeVerifier));
    expect(new URL(r.url).searchParams.get("code_challenge")).toBe(
      expectedChallenge,
    );
  });

  it("rejects out-of-spec user-supplied verifier with typed error", async () => {
    const up = new UaePassClient(baseCfg);
    await expect(
      up.buildAuthorizationUrl({ codeVerifier: "too-short" }),
    ).rejects.toThrow(UaePassConfigurationError);
  });
});

// ─────────── exchangeCodeForToken ───────────

describe("UaePassClient.exchangeCodeForToken", () => {
  it("POSTs urlencoded + Basic auth and parses the response", async () => {
    const fetchMock = fixedFetchMock(() =>
      makeResponse({
        access_token: "tok-1",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "urn:uae:digitalid:profile:general",
      }),
    );
    const up = new UaePassClient({ ...baseCfg, fetch: fetchMock });
    const tok = await up.exchangeCodeForToken({
      code: "code-1",
      codeVerifier: "verifier-1".padEnd(64, "A"),
    });
    expect(tok.access_token).toBe("tok-1");
    expect(tok.token_type).toBe("Bearer");
    expect(tok.expires_in).toBe(3600);

    expect(fetchMock).toHaveBeenCalled();
    const call = fetchMock.mock.calls[0];
    expect(call).toBeDefined();
    const calledUrl = String(call?.[0]);
    const calledInit = call?.[1] as RequestInit;
    expect(calledUrl).toBe("https://stg-id.uaepass.ae/idshub/token");
    expect(String(calledInit.body)).toContain("grant_type=authorization_code");
    expect(String(calledInit.body)).toContain("code=code-1");
    const auth = (calledInit.headers as Record<string, string>).Authorization;
    expect(auth).toMatch(/^Basic /);
    expect(auth).toBeDefined();
    expect(atob((auth as string).slice("Basic ".length))).toBe(
      "test_client:test_secret",
    );
  });

  it("401 with OAuth error shape → UaePassOAuthError (invalid_grant)", async () => {
    const fetchMock = fixedFetchMock(() =>
      makeResponse(
        { error: "invalid_grant", error_description: "expired code" },
        400,
      ),
    );
    const up = new UaePassClient({ ...baseCfg, fetch: fetchMock });
    await expect(
      up.exchangeCodeForToken({
        code: "x",
        codeVerifier: "v".padEnd(64, "B"),
      }),
    ).rejects.toMatchObject({
      name: "UaePassOAuthError",
      code: "invalid_grant",
      status: 400,
    });
  });

  it("uses injected fetch for the multipart variant too", async () => {
    const fetchMock = fixedFetchMock(() =>
      makeResponse({
        access_token: "tok-multi",
        token_type: "Bearer",
        expires_in: 1800,
        scope: "sig",
      }),
    );
    const up = new UaePassClient({ ...baseCfg, fetch: fetchMock });
    const tok = await up.exchangeCodeForToken({
      code: "c",
      codeVerifier: "v".padEnd(64, "C"),
      multipart: true,
    });
    expect(tok.access_token).toBe("tok-multi");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects empty code or verifier with typed error", async () => {
    const up = new UaePassClient(baseCfg);
    await expect(
      up.exchangeCodeForToken({ code: "", codeVerifier: "v" }),
    ).rejects.toThrow(UaePassConfigurationError);
    await expect(
      up.exchangeCodeForToken({ code: "c", codeVerifier: "" }),
    ).rejects.toThrow(UaePassConfigurationError);
  });

  it("validates the access-token response shape (asAccessTokenResponse wired)", async () => {
    const up = new UaePassClient({
      ...baseCfg,
      fetch: fixedFetchMock(() =>
        // Missing `expires_in` and `scope` — should be rejected by the
        // wired validator, not silently accepted by the generic JSON cast.
        makeResponse({ access_token: "tok", token_type: "Bearer" }),
      ),
    });
    await expect(
      up.exchangeCodeForToken({
        code: "c",
        codeVerifier: "v".padEnd(64, "x"),
      }),
    ).rejects.toMatchObject({ name: "UaePassError", code: "invalid_response" });
  });
});

// ─────────── getUserInfo ───────────

describe("UaePassClient.getUserInfo", () => {
  it("honours the injected fetch (issue #3 from review)", async () => {
    const fetchMock = fixedFetchMock(() =>
      makeResponse({
        sub: "u-1",
        uuid: "u-1",
        userType: "SOP3",
        email: "x@y.z",
        idn: "7840000",
        idType: "ID",
        firstnameEN: "F",
        lastnameEN: "L",
        fullnameEN: "Full",
        firstnameAR: "ع",
        lastnameAR: "ل",
        fullnameAR: "الاسم",
        gender: "M",
        mobile: "9715",
        nationalityEN: "ARE",
        nationalityAR: "إماراتي",
      }),
    );
    const up = new UaePassClient({ ...baseCfg, fetch: fetchMock });
    const p = await up.getUserInfo("tok");
    expect(isCitizen(p)).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("maps a visitor profile correctly", async () => {
    const fetchMock = fixedFetchMock(() =>
      makeResponse({
        sub: "v-1",
        userType: "SOP3",
        profileType: "2",
        unifiedID: "777",
        firstnameEN: "A",
        lastnameEN: "B",
        fullnameEN: "AB",
      }),
    );
    const up = new UaePassClient({ ...baseCfg, fetch: fetchMock });
    const p = await up.getUserInfo("tok");
    expect(isVisitor(p)).toBe(true);
  });
});

// ─────────── completeLogin ───────────

describe("UaePassClient.completeLogin", () => {
  it("verifies state, exchanges code, then fetches profile", async () => {
    const fetchMock = vi.fn(async (url: string | URL) => {
      const s = String(url);
      if (s.includes("/token")) {
        return makeResponse({
          access_token: "tok-final",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "urn:uae:digitalid:profile:general",
        });
      }
      if (s.includes("/userinfo")) {
        return makeResponse({
          sub: "complete-1",
          userType: "SOP3",
          idn: "7840000",
          idType: "ID",
          firstnameEN: "F",
          lastnameEN: "L",
          fullnameEN: "Full",
          firstnameAR: "ع",
          lastnameAR: "ل",
          fullnameAR: "الاسم",
          gender: "M",
          mobile: "9715",
          nationalityEN: "ARE",
          nationalityAR: "إماراتي",
        });
      }
      throw new Error("Unexpected URL: " + s);
    });
    const up = new UaePassClient({ ...baseCfg, fetch: fetchMock as unknown as typeof fetch });
    const login = await up.completeLogin({
      code: "code",
      state: "match-me",
      storedState: "match-me",
      storedVerifier: "verifier".padEnd(64, "x"),
    });
    expect(login.accessToken).toBe("tok-final");
    expect(login.profile.sub).toBe("complete-1");
    expect(login.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("throws UaePassStateError on state mismatch", async () => {
    const up = new UaePassClient(baseCfg);
    await expect(
      up.completeLogin({
        code: "c",
        state: "different",
        storedState: "different2",
        storedVerifier: "v".padEnd(64, "x"),
      }),
    ).rejects.toThrow(UaePassStateError);
  });
});

// ─────────── logout ───────────

describe("UaePassClient.buildLogoutUrl", () => {
  it("emits the standard idshub/logout URL with extra params", () => {
    const up = new UaePassClient(baseCfg);
    const u = up.buildLogoutUrl({
      postLogoutRedirectUri: "https://example.com/back",
      state: "csr",
    });
    const parsed = new URL(u);
    expect(parsed.pathname).toBe("/idshub/logout");
    expect(parsed.searchParams.get("post_logout_redirect_uri")).toBe(
      "https://example.com/back",
    );
    expect(parsed.searchParams.get("state")).toBe("csr");
  });
});

// ─────────── constructor DI ───────────

describe("UaePassClient constructor", () => {
  it("rejects empty strings via UaePassConfigurationError", () => {
    expect(
      () => new UaePassClient({ ...baseCfg, clientId: "" }),
    ).toThrow(UaePassConfigurationError);
    expect(
      () => new UaePassClient({ ...baseCfg, clientSecret: "" }),
    ).toThrow(UaePassConfigurationError);
    expect(
      () => new UaePassClient({ ...baseCfg, redirectUri: "" }),
    ).toThrow(UaePassConfigurationError);
  });
  it("rejects non-string types at runtime", () => {
    expect(
      () =>
        new UaePassClient({
          ...baseCfg,
          clientId: undefined as unknown as string,
        }),
    ).toThrow(UaePassConfigurationError);
    expect(
      () =>
        new UaePassClient({
          ...baseCfg,
          clientId: 42 as unknown as string,
        }),
    ).toThrow(UaePassConfigurationError);
  });
});

// ─────────── HttpClient ───────────

describe("HttpClient", () => {
  it("network failures become UaePassNetworkError", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("ECONNRESET");
    });
    const h = new HttpClient("https://x.test/api", fetchMock as unknown as typeof fetch);
    await expect(h.request<{ ok: boolean }>()).rejects.toBeInstanceOf(
      UaePassNetworkError,
    );
  });
  it("non-2xx becomes UaePassHttpError", async () => {
    const fetchMock = fixedFetchMock(() => makeResponse("nope", 502));
    const h = new HttpClient("https://x.test/api", fetchMock as unknown as typeof fetch);
    await expect(h.request()).rejects.toBeInstanceOf(UaePassHttpError);
  });
  it("JSON parse failures become UaePassError invalid_response", async () => {
    const fetchMock = fixedFetchMock(() => makeResponse("not-json", 200));
    const h = new HttpClient("https://x.test/api", fetchMock as unknown as typeof fetch);
    await expect(h.request()).rejects.toMatchObject({
      name: "UaePassError",
      code: "invalid_response",
    });
  });
  it("forwards AbortSignal to fetch", async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn(async (_u: string, init: RequestInit) => {
      expect(init.signal).toBe(controller.signal);
      return makeResponse({ ok: true });
    });
    const h = new HttpClient("https://x.test/api", fetchMock as unknown as typeof fetch);
    await h.request({ signal: controller.signal });
  });
});

// ─────────── UaePass alias + isUaePassError ───────────

describe("UaePass alias & isUaePassError", () => {
  it("UaePass equals UaePassClient", () => {
    expect(UaePass).toBe(UaePassClient);
  });
  it("isUaePassError narrows correctly", () => {
    try {
      throw new UaePassConfigurationError("nope");
    } catch (err) {
      expect(isUaePassError(err)).toBe(true);
      expect(err).toBeInstanceOf(UaePassError);
    }
  });
});
