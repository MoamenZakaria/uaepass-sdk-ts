/**
 * Framework-free demo using stock `node:http`.
 *
 * Run:
 *   UAE_PASS_ENV=staging \
 *   UAE_PASS_CLIENT_ID=sandbox_stage \
 *   UAE_PASS_CLIENT_SECRET=sandbox_stage \
 *   UAE_PASS_REDIRECT_URI=http://localhost:3000/callback \
 *   npx tsx examples/node-http-server.ts
 *
 * Open http://localhost:3000/login to try it.
 *
 * The session store here is a trivial in-memory Map — swap for Redis /
 * a signed cookie / JWT in production.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { UaePassClient } from "../src/auth.js";
import { fromEnv } from "../src/node.js";

const up: UaePassClient = fromEnv();

/** Tiny in-memory session store for the demo. NOT for production. */
const sessions = new Map<
  string,
  { state: string; codeVerifier: string; created: number }
>();

const SESSION_TTL_MS = 10 * 60 * 1000;

function newSessionId() {
  return Math.random().toString(36).slice(2);
}

function cookieHeader(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const setSid = (sid: string) => {
      res.setHeader(
        "Set-Cookie",
        cookieHeader("up_sid", sid, Math.floor(SESSION_TTL_MS / 1000)),
      );
    };

    if (url.pathname === "/login" && req.method === "GET") {
      const sid = newSessionId();
      const built = await up.buildAuthorizationUrl();
      sessions.set(sid, {
        state: built.state,
        codeVerifier: built.codeVerifier,
        created: Date.now(),
      });
      setSid(sid);
      res.writeHead(302, { Location: built.url });
      res.end();
      return;
    }

    if (url.pathname === "/callback" && req.method === "GET") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!code || !state) {
        respond(res, 400, "Missing `code` or `state`");
        return;
      }
      // Look up the session by cookie.
      const sid = readCookie(req, "up_sid");
      const stored = sid ? sessions.get(sid) : undefined;
      if (!stored) {
        respond(res, 400, "No session in progress");
        return;
      }
      sessions.delete(sid!);
      res.setHeader("Set-Cookie", "up_sid=; Path=/; Max-Age=0");

      const login = await up.completeLogin({
        code,
        state,
        storedState: stored.state,
        storedVerifier: stored.codeVerifier,
      });

      respond(
        res,
        200,
        `Logged in ✅\nsub=${login.profile.sub}\nuserType=${
          (login.profile as { userType: string }).userType
        }\nexpiresAt=${login.expiresAt.toISOString()}`,
      );
      return;
    }

    if (url.pathname === "/logout" && req.method === "GET") {
      const url2 = up.buildLogoutUrl({
        postLogoutRedirectUri: up.getEndpoints().logout,
      });
      res.writeHead(302, { Location: url2 });
      res.end();
      return;
    }

    if (url.pathname === "/" && req.method === "GET") {
      respond(
        res,
        200,
        `<a href="/login">Login with UAE PASS</a> · <a href="/logout">Logout</a>`,
      );
      return;
    }

    respond(res, 404, "Not Found");
  } catch (err) {
    console.error(err);
    respond(res, 500, (err as Error).message);
  }
});

// Periodically prune expired sessions.
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (now - s.created > SESSION_TTL_MS) sessions.delete(sid);
  }
}, 60_000).unref();

server.listen(3000, () => {
  console.log("UAE PASS demo on http://localhost:3000/login");
});

function readCookie(
  req: IncomingMessage,
  name: string,
): string | undefined {
  const raw = req.headers.cookie;
  if (!raw) return undefined;
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

function respond(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(body);
}
