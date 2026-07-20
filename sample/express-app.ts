/**
 * Minimal Express demo — drop-in starter for the UAE PASS flow.
 *
 * Run:
 *   cp .env.example .env   # then fill in `UAE_PASS_*` values
 *   npx tsx sample/express-app.ts
 *
 * Then open: http://localhost:3000/login
 */

import express from "express";
import cookieParser from "cookie-parser";
import type { Request, Response } from "express";
import { UaePass } from "../src/index.js";
import type { CompletedLogin, AccessTokenResponse } from "../src/index.js";

const app = express();
app.use(cookieParser());

// Reads `UAE_PASS_ENV`, `UAE_PASS_CLIENT_ID`, `UAE_PASS_CLIENT_SECRET`,
// `UAE_PASS_REDIRECT_URI` from process.env (or `.env` via your loader).
const up = UaePass.fromEnv();

app.get("/", (_req, res) => {
  res.type("html").send(`
    <h1>UAE PASS demo</h1>
    <p><a href="/login">Login with UAE PASS</a></p>
    <hr/>
  `);
});

/**
 * The router types callbacks as `(req, res)` where `req`/`res` are
 * `unknown` to keep the SDK zero-dep. In an Express app we bridge them
 * here with a real `(Request, Response) => …` shape.
 */
app.use(
  up.expressRouter({
    onLogin: (async (req: Request, res: Response, ctx: { profile: any; tokens: AccessTokenResponse }) => {
      console.log(
        `[UAE PASS] login OK: sub=${ctx.profile.sub} userType=${ctx.profile.userType}`,
      );
      console.log(`[UAE PASS]   expires in ${ctx.tokens.expires_in}s`);
      (req as unknown as { session: { userId: string } }).session.userId =
        ctx.profile.sub;
    }) as unknown as Parameters<typeof up.expressRouter>[0]["onLogin"],
    onError: ((req: Request, res: Response, err: unknown) => {
      console.error("[UAE PASS] error", err);
      res.redirect("/?error=uaepass");
    }) as unknown as Parameters<typeof up.expressRouter>[0]["onError"],
    successRedirect: "/profile",
    failureRedirect: "/?error=login",
  }),
);


app.get("/profile", (_req, res) => {
  res.type("html").send(`
    <h2>Logged in 🎉</h2>
    <p>Check the server console for your UAE PASS profile.</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`UAE PASS demo listening on http://localhost:${port}`);
});
