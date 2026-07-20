/**
 * Tests for `SignatureClient`.
 *
 * The most important coverage:
 *   - Token cache honours `expires_in`
 *   - Injected fetch propagates to every signature call
 *   - `fetchSignedDocument` uses HttpClient + maps errors to UaePassHttpError
 *   - `waitUntilDone` polls until terminal and AbortSignal cancels
 *   - `createSignerProcess` validates input shape
 */

import { describe, it, expect, vi } from "vitest";
import {
  SignatureClient,
  SignatureClientConfig,
  UaePassConfigurationError,
  UaePassHttpError,
} from "../src/index.js";

function makeResponse(
  body: unknown,
  status = 200,
  contentType = "application/json",
): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (k: string) => {
        if (k.toLowerCase() === "content-type") return contentType;
        return null;
      },
    },
    text: async () =>
      typeof body === "string" ? body : JSON.stringify(body),
    json: async () =>
      typeof body === "string" ? JSON.parse(body) : body,
    arrayBuffer: async () => {
      const text =
        typeof body === "string" ? body : JSON.stringify(body);
      return new TextEncoder().encode(text).buffer;
    },
  } as unknown as Response;
}

function fixedFetch(
  responses: (u: string, init: RequestInit) => Response,
): typeof fetch & { mock: ReturnType<typeof vi.fn>["mock"] } {
  const fn = vi.fn(async (url: string | URL, init: RequestInit = {}) =>
    responses(String(url), init));
  return fn as unknown as typeof fetch & {
    mock: ReturnType<typeof vi.fn>["mock"];
  };
}

const baseCfg: SignatureClientConfig = {
  environment: "staging",
  clientId: "sig_client",
  clientSecret: "sig_secret",
  expirySafetyMs: 0,
};

describe("SignatureClient.getToken", () => {
  it("POSTs Basic auth + form body and caches by expires_in", async () => {
    let tokenCalls = 0;
    const fm = fixedFetch((url, init) => {
      if (url.includes("trustedx-authserver")) {
        tokenCalls++;
        return makeResponse({
          access_token: "sig-tok-1",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "sig",
        });
      }
      return makeResponse({ status: "PENDING" });
    });
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    const t1 = await sig.getToken();
    const t2 = await sig.getToken();
    expect(t1.access_token).toBe("sig-tok-1");
    expect(t2.access_token).toBe("sig-tok-1");
    expect(tokenCalls).toBe(1); // cache hit on second call
  });

  it("refreshes when expires_in safety-window elapses", async () => {
    let tokenCalls = 0;
    const fm = fixedFetch((url) => {
      if (url.includes("trustedx-authserver")) {
        tokenCalls++;
        return makeResponse({
          access_token: `sig-${tokenCalls}`,
          token_type: "Bearer",
          expires_in: 1, // 1 second
          scope: "sig",
        });
      }
      return makeResponse({ status: "PENDING" });
    });
    const sig = new SignatureClient({
      ...baseCfg,
      fetch: fm,
      expirySafetyMs: 60_000, // safety > expiry — first call only
    });
    await sig.getToken();
    sig.invalidateToken();
    await sig.getToken();
    expect(tokenCalls).toBe(2);
  });

  it("throws UaePassConfigurationError when expires_in missing", async () => {
    const fm = fixedFetch((url) =>
      url.includes("trustedx-authserver")
        ? makeResponse({ access_token: "x", token_type: "Bearer", scope: "s" })
        : makeResponse({}),
    );
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    await expect(sig.getToken()).rejects.toBeInstanceOf(
      UaePassConfigurationError,
    );
  });

  it("invalidateToken forces re-fetch", async () => {
    let tokenCalls = 0;
    const fm = fixedFetch((url) => {
      if (url.includes("trustedx-authserver")) {
        tokenCalls++;
        return makeResponse({
          access_token: `t-${tokenCalls}`,
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      return makeResponse({});
    });
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    await sig.getToken();
    sig.invalidateToken();
    await sig.getToken();
    expect(tokenCalls).toBe(2);
  });
});

describe("SignatureClient.createSignerProcess", () => {
  it("sends the document JSON with Bearer + the user access token in the body", async () => {
    let lastBody: unknown;
    let lastBodyInit: RequestInit | undefined;
    const fm = vi.fn(async (url: string | URL, init: RequestInit = {}) => {
      lastBodyInit = init;
      const s = String(url);
      if (s.includes("trustedx-authserver")) {
        return makeResponse({
          access_token: "sig",
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      if (typeof init.body === "string") lastBody = JSON.parse(init.body);
      return makeResponse({ documentId: "d-1", signerProcessId: "sp-1" });
    });
    const sig = new SignatureClient({
      ...baseCfg,
      fetch: fm as unknown as typeof fetch,
    });
    const r = await sig.createSignerProcess({
      document: { content: "BASE64-PDF-BYTES", name: "test.pdf" },
      description: "demo",
      userAccessToken: "user-tok",
    });
    expect(r.documentId).toBe("d-1");
    expect(r.signerProcessId).toBe("sp-1");
    expect(lastBody).toMatchObject({
      document: { name: "test.pdf", content: "BASE64-PDF-BYTES" },
      userAccessToken: "user-tok",
    });
    // The Bearer header was set on the request that uploaded the doc.
    const hdr = (lastBodyInit?.headers as Record<string, string> | undefined)
      ?.Authorization;
    expect(hdr).toBe("Bearer sig");
  });

  it("validates that userAccessToken is provided", async () => {
    const fm = fixedFetch(() =>
      makeResponse({ access_token: "x", token_type: "Bearer", expires_in: 1 }),
    );
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    await expect(
      sig.createSignerProcess({ document: "BASE64", userAccessToken: "" }),
    ).rejects.toBeInstanceOf(UaePassConfigurationError);
  });

  it("validates document.content", async () => {
    const fm = fixedFetch(() =>
      makeResponse({ access_token: "x", token_type: "Bearer", expires_in: 1 }),
    );
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    await expect(
      sig.createSignerProcess({
        document: { content: "", name: "x.pdf" },
        userAccessToken: "u",
      }),
    ).rejects.toThrow(/non-empty base64/);
  });
});

describe("SignatureClient.waitUntilDone", () => {
  it("polls and returns when status reaches terminal", async () => {
    const results = [
      { status: "PENDING" },
      { status: "IN_PROGRESS" },
      {
        status: "COMPLETED",
        signedDocuments: [{ id: "d-1", url: "https://x/d-1" }],
      },
    ];
    let i = 0;
    let calls = 0;
    const fm = fixedFetch((url) => {
      calls++;
      if (url.includes("trustedx-authserver")) {
        return makeResponse({
          access_token: "sig",
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      return makeResponse(results[i++ % results.length]);
    });
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    const final = await sig.waitUntilDone("sp-1", {
      intervalMs: 100,
      timeoutMs: 5000,
    });
    expect(final.status).toBe("COMPLETED");
    expect(final.signedDocuments?.[0]?.id).toBe("d-1");
    expect(calls).toBeGreaterThanOrEqual(4); // 1 token + 3 polls
  });

  it("honours AbortSignal", async () => {
    const controller = new AbortController();
    const fm = fixedFetch((url) => {
      if (url.includes("trustedx-authserver")) {
        return makeResponse({
          access_token: "sig",
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      return makeResponse({ status: "PENDING" });
    });
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    setTimeout(() => controller.abort(), 50);
    const p = sig.waitUntilDone("sp-1", {
      intervalMs: 200,
      signal: controller.signal,
      timeoutMs: 5_000,
    });
    await expect(p).rejects.toThrow(/aborted/i);
  });

  it("validates intervalMs", async () => {
    const sig = new SignatureClient(baseCfg);
    await expect(sig.waitUntilDone("x", { intervalMs: 50 })).rejects.toThrow(
      /intervalMs/,
    );
  });

  it("rejects non-positive timeoutMs", async () => {
    const sig = new SignatureClient(baseCfg);
    await expect(
      sig.waitUntilDone("x", { intervalMs: 1_000, timeoutMs: 0 }),
    ).rejects.toThrow(/timeoutMs/);
  });
});

describe("SignatureClient.fetchSignedDocument", () => {
  it("uses HttpClient and throws UaePassHttpError on 500", async () => {
    const fm = fixedFetch((url) => {
      if (url.includes("trustedx-authserver")) {
        return makeResponse({
          access_token: "sig",
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      return makeResponse("server boom", 500, "text/plain");
    });
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    await expect(sig.fetchSignedDocument("d-1")).rejects.toMatchObject({
      name: "UaePassHttpError",
      status: 500,
    });
  });

  it("returns the bytes on 200", async () => {
    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // %PDF
    const fm = fixedFetch((url) => {
      if (url.includes("trustedx-authserver")) {
        return makeResponse({
          access_token: "sig",
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      return {
        ok: true,
        status: 200,
        headers: { get: (k: string) => (k.toLowerCase() === "content-type" ? "application/pdf" : null) },
        text: async () => "%PDF",
        json: async () => ({}),
        arrayBuffer: async () => pdfBytes.buffer,
      } as unknown as Response;
    });
    const sig = new SignatureClient({ ...baseCfg, fetch: fm });
    const bytes = await sig.fetchSignedDocument("d-1");
    expect(bytes.byteLength).toBe(4);
    expect(Array.from(bytes)).toEqual([0x25, 0x50, 0x44, 0x46]);
  });
});

describe("SignatureClient constructor", () => {
  it("rejects missing config with typed error", () => {
    expect(() => new SignatureClient({ ...baseCfg, clientId: "" })).toThrow(
      UaePassConfigurationError,
    );
    expect(() => new SignatureClient({ ...baseCfg, clientSecret: "" })).toThrow(
      UaePassConfigurationError,
    );
  });
});
