/**
 * `@uaepass/sdk-ts/node` — Node-specific convenience exports.
 *
 * Bundling note: apps that only target the browser should NOT import
 * this file — it reads `process.env`. Use `import { UaePass } from
 * "@uaepass/sdk-ts"` for the portable core.
 */

import { UaePassClient } from "./auth.js";
import {
  UaePassConfigurationError,
  UaePassError,
} from "./errors.js";
import { parseEnvironment } from "./endpoints.js";

/**
 * Env-var mapping read by `fromEnv()`.
 * Override any field by passing it explicitly — remaining fields
 * fall back to `process.env.UAE_PASS_*`.
 */
export interface UaePassEnvConfig {
  /** @default `process.env.UAE_PASS_ENV` */
  environment?: string;
  /** @default `process.env.UAE_PASS_CLIENT_ID` */
  clientId?: string;
  /** @default `process.env.UAE_PASS_CLIENT_SECRET` */
  clientSecret?: string;
  /** @default `process.env.UAE_PASS_REDIRECT_URI` */
  redirectUri?: string;
}

function env(name: string): string | undefined {
  const v = process.env[name];
  return v && v.length > 0 ? v : undefined;
}

/**
 * Construct a `UaePassClient` from environment variables.
 *
 * Required vars (or pass overrides):
 *   UAE_PASS_ENV          "staging" | "production"
 *   UAE_PASS_CLIENT_ID    from the self-care portal
 *   UAE_PASS_CLIENT_SECRET from the self-care portal
 *   UAE_PASS_REDIRECT_URI match the portal registration exactly
 *
 * Throws `UaePassConfigurationError` if anything required is missing.
 *
 * @example
 * ```ts
 * import { fromEnv } from "@uaepass/sdk-ts/node";
 * const up = fromEnv();
 * ```
 */
export function fromEnv(overrides: UaePassEnvConfig = {}): UaePassClient {
  const environment = overrides.environment ?? env("UAE_PASS_ENV") ?? "staging";
  const clientId = overrides.clientId ?? env("UAE_PASS_CLIENT_ID");
  const clientSecret = overrides.clientSecret ?? env("UAE_PASS_CLIENT_SECRET");
  const redirectUri = overrides.redirectUri ?? env("UAE_PASS_REDIRECT_URI");

  const missing: string[] = [];
  if (!clientId) missing.push("UAE_PASS_CLIENT_ID");
  if (!clientSecret) missing.push("UAE_PASS_CLIENT_SECRET");
  if (!redirectUri) missing.push("UAE_PASS_REDIRECT_URI");
  if (missing.length > 0) {
    throw new UaePassConfigurationError(
      `fromEnv: missing required env: ${missing.join(", ")}`,
    );
  }

  try {
    return new UaePassClient({
      environment: parseEnvironment(environment),
      clientId: clientId!,
      clientSecret: clientSecret!,
      redirectUri: redirectUri!,
    });
  } catch (err) {
    if (err instanceof UaePassError) throw err;
    throw new UaePassConfigurationError(
      `fromEnv: failed to construct client: ${(err as Error).message}`,
    );
  }
}

export { UaePassClient };
// Convenience alias matching the main entry-point import name.
export const UaePass = UaePassClient;
export default UaePassClient;
