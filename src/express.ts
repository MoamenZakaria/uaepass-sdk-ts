/**
 * Plug-and-play Express helpers for the OAuth flow.
 *
 *   import express from "express";
 *   import { UaePassClient } from "@uaepass/sdk-ts";
 *   import { createUaePassRouter } from "@uaepass/sdk-ts/express";
 *
 *   const up = new UaePassClient({ clientId, clientSecret, redirectUri });
 *   const app = express();
 *   app.use("/uaepass", createUaePassRouter({
 *     client: up,
 *     onLogin: async (req, profile, tokens) => { ... },
 *     onError:  (req, err) => { ... },
 *   }));
 *
 * The router mounts three routes: `/login`, `/callback`, `/logout`.
 *
 * State + PKCE verifier are stored in an HMAC-signed `up_state` cookie —
 * no session middleware required.
 */

import type { Request, Response, Router } from "express";
import { randomBytes, createHmac } from "node:crypto";
import type { UaePassClient, AuthorizationRequestInit } from "./auth.js";
import type { UaePassProfile, AccessTokenResponse, UaePassSessionStore } from "./types.js";

const COOKIE_NAME = "up_state";

/** Express-typed alias for `UaePassSessionStore`. */
export type ExpressSessionStore = UaePassSessionStore<
  Request,
  Response
>;


/** Build the default cookie-backed session store. */
export function cookieSessionStore(
  secret: string,
): UaePassSessionStore<Request, Response> {
  const sig = (value: string) =>
    createHmac("sha256", secret).update(value).digest("base64url");
  const encode = (payload: { state: string; verifier: string }) => {
    const raw = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    return `${raw}.${sig(raw)}`;
  };
  const decode = (cookie: string): { state: string; verifier: string } | null => {
    const dot = cookie.lastIndexOf(".");
    if (dot < 0) return null;
    const raw = cookie.slice(0, dot);
    const want = cookie.slice(dot + 1);
    if (sig(raw) !== want) return null;
    try {
      return JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
    } catch {
      return null;
    }
  };

  return {
    load(req) {
      const c = (req as { cookies?: Record<string, string> }).cookies?.[COOKIE_NAME];
      if (!c || typeof c !== "string") return null;
      return decode(c);
    },
    save(res, payload) {
      (res as unknown as {
        cookie: (n: string, v: string, opts: object) => void;
      }).cookie(COOKIE_NAME, encode(payload), {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        path: "/",
        maxAge: 10 * 60 * 1000, // 10 min — enough for the round-trip
      });
    },
    clear(res) {
      (res as unknown as {
        clearCookie: (n: string, opts: object) => void;
      }).clearCookie(COOKIE_NAME, { path: "/" });
    },
  };
}

export interface UaePassRouterOptions {
  client: UaePassClient;
  /** Mount path prefix (defaults to `/`). */
  path?: string;
  /** Express-typed session store; defaults to a signed cookie. */
  session?: ExpressSessionStore;
  /**
   * Invoked after a successful login / token / userinfo.
   * - `tokens` is the raw access-token response from UAE PASS.
   */
  onLogin: (
    req: Request,
    res: Response,
    ctx: { profile: UaePassProfile; tokens: AccessTokenResponse },
  ) => void | Promise<void>;
  /** Optional error handler. Receives the error and writes the response. */
  onError?: (req: Request, res: Response, err: unknown) => void;
  /** Final redirect after `onLogin` resolves. Defaults to `/`. */
  successRedirect?: string;
  /** Final redirect on failure. Defaults to `/`. */
  failureRedirect?: string;
  /** Where to send the user after UAE PASS `/idshub/logout`. */
  logoutRedirectUri: string;
  /** Scope(s) to request at `/login`. */
  scope?: AuthorizationRequestInit["scope"];
  /** ACR(s) for the authorisation request. */
  acrValues?: AuthorizationRequestInit["acrValues"];
  /** UI locale (`en` / `ar`). */
  uiLocales?: "en" | "ar";
}

/**
 * Build an Express router that wires `/login`, `/callback`, `/logout`.
 *
 * Requires `cookie-parser` middleware upstream (so `req.cookies` exists)
 * or any middleware that populates `req.cookies`.
 */
export function createUaePassRouter(
  opts: UaePassRouterOptions,
): Router {
  // Dynamic import so the SDK is usable without Express as a hard dep.
  // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
  const express = require("express") as typeof import("express");
  const router: Router = (express.Router as unknown as () => Router)();
  router.use?.((_req, _res, next) => next()); // no-op, for symmetry

  const session = opts.session ?? cookieSessionStore(secretFromEnv());
  const successRedirect = opts.successRedirect ?? "/";
  const failureRedirect = opts.failureRedirect ?? "/";

  router.get("/login", async (req, res) => {
    try {
      const init: AuthorizationRequestInit = {};
      if (opts.scope !== undefined) init.scope = opts.scope;
      if (opts.acrValues !== undefined) init.acrValues = opts.acrValues;
      if (opts.uiLocales !== undefined) init.uiLocales = opts.uiLocales;
      const built = await opts.client.buildAuthorizationUrl(init);
      session.save(res, { state: built.state, verifier: built.codeVerifier });
      res.redirect(built.url);
    } catch (err) {
      opts.onError
        ? opts.onError(req, res, err)
        : res.status(500).send(`UAE PASS login error: ${(err as Error).message}`);
    }
  });

  router.get("/callback", async (req, res) => {
    try {
      const stored = session.load(req);
      session.clear(res);
      if (!stored) throw new Error("No UAE PASS session in progress");
      const code = stringParam(req.query.code);
      const state = stringParam(req.query.state);
      if (!code) throw new Error("Missing `code` from UAE PASS");
      if (!state) throw new Error("Missing `state` from UAE PASS");
      opts.client.verifyState(stored.state, state);

      const tokens = await opts.client.exchangeCodeForToken({
        code,
        codeVerifier: stored.verifier,
      });
      const profile = await opts.client.getUserInfo(tokens.access_token);
      await opts.onLogin(req, res, { profile, tokens });
      // If onLogin didn't end the response, redirect.
      if (!res.headersSent) res.redirect(successRedirect);
    } catch (err) {
      if (opts.onError) {
        opts.onError(req, res, err);
      } else {
        res.status(400).send(`UAE PASS callback error: ${(err as Error).message}`);
      }
    }
  });

  router.get("/logout", (req, res) => {
    const url = opts.client.buildLogoutUrl({
      postLogoutRedirectUri: opts.logoutRedirectUri,
      state: randomBytes(8).toString("base64url"),
    });
    res.redirect(url);
  });

  return router;
}

function stringParam(v: unknown): string | undefined {
  if (typeof v === "string" && v.length > 0) return v;
  if (Array.isArray(v) && typeof v[0] === "string") return v[0];
  return undefined;
}

function secretFromEnv(): string {
  const s = process.env.SESSION_SECRET || process.env.UAE_PASS_SESSION_SECRET;
  if (s && s.length >= 16) return s;
  // Dev fallback — fine to log a warning in non-prod.
  if (process.env.NODE_ENV !== "production") {
    // eslint-disable-next-line no-console
    console.warn(
      "[uaepass/sdk-ts] SESSION_SECRET not set; using insecure dev fallback.",
    );
    return "dev-only-insecure-secret";
  }
  throw new Error(
    "SESSION_SECRET env var (≥16 chars) is required in production.",
  );
}
