import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  UaePassClient,
  UaePassStateError,
  resolveEndpoints,
  parseEnvironment,
  createPkcePair,
  safeStringEqual,
  base64UrlEncode,
  randomUrlSafe,
} from "../src/index.js";
import { HttpClient } from "../src/http.js";

function makeFetchJson(body: unknown, status = 200) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k: string) => (k === "content-type" ? "application/json" : null) },
    json: async () => body,
    text: async () => JSON.stringify(body),
    arrayBuffer: async () => new ArrayBuffer(0),
  } as unknown as Response));
}

describe("parseEnvironment", () => {
  it("defaults to staging", () => {
    expect(parseEnvironment(undefined)).toBe("staging");
  });
  it("accepts production", () => {
    expect(parseEnvironment("production")).toBe("production");
  });
  it("throws on unknown", () => {
    expect(() => parseEnvironment("bogus")).toThrow(/Unknown UAE PASS environment/);
  });
});

describe("resolveEndpoints", () => {
  it("returns staging hostnames", () => {
    const e = resolveEndpoints("staging");
    expect(e.authorize).toContain("stg-id.uaepass.ae/idshub/authorize");
    expect(e.signerProcesses).toContain("/trustedx-resources/esignsp/v2/signer_processes");
  });
  it("returns production hostnames", () => {
    const e = resolveEndpoints("production");
    expect(e.authorize).toBe("https://id.uaepass.ae/idshub/authorize");
  });
  it("builds parameterised signing URLs", () => {
    const e = resolveEndpoints("staging");
    expect(e.signerResult("abc-123")).toContain("signer_processes/abc-123/result");
    expect(e.signedDocument("doc-99")).toContain("documents/doc-99/content");
  });
});

describe("createPkcePair", () => {
  it("produces a 43–128 char verifier + S256 challenge", async () => {
    const p = await createPkcePair(64);
    expect(p.codeVerifier.length).toBe(64);
    expect(p.codeChallengeMethod).toBe("S256");
    expect(p.codeChallenge.length).toBeGreaterThanOrEqual(43);
  });
  it("rejects out-of-range verifier lengths", async () => {
    await expect(createPkcePair(20)).rejects.toThrow(/between 43 and 128/);
    await expect(createPkcePair(200)).rejects.toThrow(/between 43 and 128/);
  });
});

describe("crypto", () => {
  it("safeStringEqual matches and mismatches correctly", () => {
    expect(safeStringEqual("a", "a")).toBe(true);
    expect(safeStringEqual("a", "b")).toBe(false);
    expect(safeStringEqual("aa", "a")).toBe(false);
  });
  it("randomUrlSafe yields url-safe characters", () => {
    const r = randomUrlSafe(48);
    expect(r).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });
  it("base64UrlEncode strips padding", () => {
    expect(base64UrlEncode("aa?")).not.toContain("=");
  });
});

describe("UaePassClient.buildAuthorizationUrl", () => {
  it("emits correct query params + PKCE challenge", async () => {
    const c = new UaePassClient({
      environment: "staging",
      clientId: "abc",
      clientSecret: "secret",
      redirectUri: "https://example/callback",
    });
    const r = await c.buildAuthorizationUrl({
      scope: ["urn:uae:digitalid:profile:general"],
      acrValues: "urn:safelayer:tws:policies:authentication:level:low",
      uiLocales: "en",
    });
    const u = new URL(r.url);
    expect(u.origin + u.pathname).toBe("https://stg-id.uaepass.ae/idshub/authorize");
    expect(u.searchParams.get("client_id")).toBe("abc");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("ui_locales")).toBe("en");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(r.codeVerifier.length).toBeGreaterThanOrEqual(43);
  });
  it("builds the visitor flow when extra profile scopes are added", async () => {
    const c = new UaePassClient({
      environment: "staging",
      clientId: "x",
      clientSecret: "y",
      redirectUri: "https://x/cb",
    });
    const r = await c.buildAuthorizationUrl({
      scope: [
        "urn:uae:digitalid:profile:general",
        "urn:uae:digitalid:profile:general:profileType",
        "urn:uae:digitalid:profile:general:unifiedId",
      ],
    });
    const u = new URL(r.url);
    expect(u.searchParams.get("scope")).toContain("unifiedId");
  });
});

describe("UaePassClient.exchangeCodeForToken", () => {
  it("sends Basic auth + urlencoded body and parses the access token", async () => {
    const fetchMock = makeFetchJson({
      access_token: "tok-1",
      token_type: "Bearer",
      expires_in: 3600,
      scope: "urn:uae:digitalid:profile:general",
    });

    const c = new UaePassClient({
      environment: "staging",
      clientId: "cid",
      clientSecret: "sec",
      redirectUri: "https://x/cb",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const tok = await c.exchangeCodeForToken({
      code: "code-1",
      codeVerifier: "verifier-1",
    });
    expect(tok.access_token).toBe("tok-1");
    expect(fetchMock).toHaveBeenCalled();
    const call = fetchMock.mock.calls[0];
    expect(call).toBeDefined();
    const [calledUrl, calledInit] = call as unknown as [string, RequestInit];
    expect(String(calledUrl)).toBe("https://stg-id.uaepass.ae/idshub/token");
    const body = String((calledInit as RequestInit).body);
    expect(body).toContain("grant_type=authorization_code");
    expect((calledInit.headers as Record<string, string>).Authorization).toMatch(
      /^Basic /,
    );
  });

  it("maps OAuth 400 errors to UaePassOAuthError", async () => {
    const fetchMock = makeFetchJson(
      { error: "invalid_grant", error_description: "expired code" },
      400,
    );
    const c = new UaePassClient({
      environment: "staging",
      clientId: "cid",
      clientSecret: "sec",
      redirectUri: "https://x/cb",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(
      c.exchangeCodeForToken({ code: "x", codeVerifier: "y" }),
    ).rejects.toMatchObject({ name: "UaePassOAuthError", code: "invalid_grant" });
  });
});

describe("verifyState", () => {
  it("compares in constant-ish time and throws on mismatch", () => {
    const c = new UaePassClient({
      clientId: "x",
      clientSecret: "y",
      redirectUri: "https://x/cb",
    });
    c.verifyState("aabb", "aabb");
    expect(() => c.verifyState("aabb", "ccdd")).toThrow(UaePassStateError);
  });
});

describe("HttpClient shape", () => {
  it("makes GET requests and returns JSON", async () => {
    const fetchMock = makeFetchJson({ hello: "world" });
    const h = new HttpClient("https://example/api", fetchMock as unknown as typeof fetch);
    const r = await h.request<{ hello: string }>();
    expect(r.hello).toBe("world");
  });
  it("wraps network failures as UaePassNetworkError", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("ECONNRESET");
    });
    const h = new HttpClient("https://example/api", fetchMock as unknown as typeof fetch);
    await expect(h.request()).rejects.toMatchObject({ name: "UaePassNetworkError" });
  });
  it("wraps non-2xx responses as UaePassHttpError", async () => {
    const fetchMock = makeFetchJson("nope", 502);
    const h = new HttpClient("https://example/api", fetchMock as unknown as typeof fetch);
    await expect(h.request()).rejects.toMatchObject({ name: "UaePassHttpError" });
  });
});
