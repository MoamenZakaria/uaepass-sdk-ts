import { describe, it, expect, vi } from "vitest";
import express from "express";
import request from "supertest";
import { UaePassClient } from "../src/index.js";
import { createUaePassRouter, cookieSessionStore } from "../src/express.js";

vi.mock("../src/auth.js", async () => {
  // Use the real client but stub low-level calls.
  return await vi.importActual<typeof import("../src/auth.js")>("../src/auth.js");
});

function buildApp(opts: Partial<Parameters<typeof createUaePassRouter>[0]> = {}) {
  const up = new UaePassClient({
    environment: "staging",
    clientId: "cid",
    clientSecret: "sec",
    redirectUri: "https://app.test/callback",
  });
  const session = cookieSessionStore("0123456789abcdef-test-secret");
  const app = express();
  app.use((req, _res, next) => {
    // supertest doesn't run cookie-parser; we manually parse a single cookie.
    const cookie = req.headers.cookie ?? "";
    const parsed: Record<string, string> = {};
    cookie.split(";").forEach((kv) => {
      const [k, ...rest] = kv.trim().split("=");
      if (k) parsed[k] = decodeURIComponent(rest.join("="));
    });
    (req as unknown as { cookies: Record<string, string> }).cookies = parsed;
    next();
  });
  app.use(
    "/up",
    createUaePassRouter({
      client: up,
      session,
      logoutRedirectUri: "https://app.test/",
      onLogin: async (_req, res) => {
        res.status(200).send("ok");
      },
      ...opts,
    }),
  );
  return app;
}

describe("createUaePassRouter", () => {
  it("/login redirects to idshub/authorize and sets the state cookie", async () => {
    const app = buildApp();
    const res = await request(app).get("/up/login").redirects(0);
    expect(res.status).toBe(302);
    const loc = res.headers.location!;
    expect(loc).toContain("stg-id.uaepass.ae/idshub/authorize");
    expect(loc).toContain("response_type=code");
    expect(loc).toContain("code_challenge=");
    expect(res.headers["set-cookie"]?.[0]).toMatch(/^up_state=/);
  });

  it("/callback returns 400 when state is missing", async () => {
    const app = buildApp();
    const res = await request(app)
      .get("/up/callback")
      .query({ code: "abc", state: "wrong" });
    expect(res.status).toBe(400);
  });

  it("/logout redirects to idshub/logout with post_logout_redirect_uri", async () => {
    const app = buildApp();
    const res = await request(app).get("/up/logout").redirects(0);
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^https:\/\/stg-id\.uaepass\.ae\/idshub\/logout/);
    expect(res.headers.location).toContain("post_logout_redirect_uri=");
  });
});
