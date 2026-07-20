import { describe, it, expect, vi } from "vitest";
import { SignatureClient } from "../src/index.js";
import { UaePassEndpoints, resolveEndpoints } from "../src/endpoints.js";

function fakeResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k: string) => headers[k.toLowerCase()] ?? null },
    json: async () => body,
    text: async () => JSON.stringify(body),
    arrayBuffer: async () => new ArrayBuffer(0),
  } as unknown as Response;
}

describe("SignatureClient.getToken", () => {
  it("POSTs client_credentials grant with Basic auth", async () => {
    const fetchMock = vi.fn(async (_url: unknown, init: any) => {
      expect(init.method).toBe("POST");
      expect(init.headers.Authorization).toMatch(/^Basic /);
      return fakeResponse(
        { access_token: "sig-tok", token_type: "Bearer", expires_in: 3600, scope: "sig" },
        200,
        { "content-type": "application/json" },
      );
    });
    const sig = new SignatureClient({
      environment: "staging",
      clientId: "cid",
      clientSecret: "sec",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const t = await sig.getToken();
    expect(t.access_token).toBe("sig-tok");
  });
});

describe("SignatureClient.createSignerProcess", () => {
  it("sends the document JSON with user access token + Bearer", async () => {
    let lastInit: any;
    const fetchMock = vi.fn(async (_url: unknown, init: any) => {
      lastInit = init;
      return fakeResponse(
        { documentId: "doc-1", signerProcessId: "sp-1" },
        200,
        { "content-type": "application/json" },
      );
    });
    const sig = new SignatureClient({
      environment: "staging",
      clientId: "cid",
      clientSecret: "sec",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await sig.getToken();
    const r = await sig.createSignerProcess({
      document: { content: "BASE64-PDF-BYTES", name: "test.pdf" },
      description: "demo",
      userAccessToken: "user-tok",
    });
    expect(r.documentId).toBe("doc-1");
    expect(r.signerProcessId).toBe("sp-1");
    const body = JSON.parse(lastInit.body);
    expect(body.userAccessToken).toBe("user-tok");
    expect(body.document.name).toBe("test.pdf");
  });
});

describe("SignatureClient.getResult / waitUntilDone", () => {
  it("polls until COMPLETED", async () => {
    const responses = [
      { status: "PENDING" },
      { status: "IN_PROGRESS" },
      { status: "COMPLETED", signedDocuments: [{ id: "d1", url: "https://x/d1" }] },
    ];
    let i = 0;
    const fetchMock = vi.fn(async () =>
      fakeResponse(responses[i++ % responses.length], 200, {
        "content-type": "application/json",
      }),
    );
    const sig = new SignatureClient({
      environment: "staging",
      clientId: "cid",
      clientSecret: "sec",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await sig.getToken();
    const final = await sig.waitUntilDone("sp-1", { intervalMs: 5, timeoutMs: 1000 });
    expect(final.status).toBe("COMPLETED");
    expect(final.signedDocuments?.[0]?.id).toBe("d1");
  });
});

describe("resolveEndpoints convenience functions", () => {
  it("returns a host-correct UaePassEndpoints for staging", () => {
    const e: UaePassEndpoints = resolveEndpoints("staging");
    expect(e.signingToken).toBe(
      "https://stg-id.uaepass.ae/trustedx-authserver/oauth/main-as/token",
    );
    expect(e.deleteSignerProcess("p")).toContain("signer_processes/p");
  });
});
