/**
 * Sentry error tracking for AgentAegis MCP server.
 *
 * MUST be imported and initialized BEFORE any other application code that
 * could throw — otherwise early errors are lost. The pattern is:
 *
 *   // src/http-server.ts
 *   import "dotenv/config";
 *   import { initSentry } from "./observability/sentry.js";
 *   initSentry();                    // <-- before any non-trivial imports
 *   import { buildHttpApp } from ...
 *
 * Idempotent: safe to call multiple times. No-op if SENTRY_DSN is unset
 * (so local development works without a Sentry account).
 */

import * as Sentry from "@sentry/node";

let initialized = false;

export function initSentry(): void {
  if (initialized) return;
  initialized = true;

  const dsn = process.env.SENTRY_DSN;
  if (!dsn) {
    // Silently no-op in environments without Sentry — local dev, CI, etc.
    return;
  }

  const environment = process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "production";
  const release = process.env.SENTRY_RELEASE || process.env.RAILWAY_GIT_COMMIT_SHA || undefined;

  Sentry.init({
    dsn,
    environment,
    release,

    // Performance: 10% sampling in production. Increase to 1.0 temporarily if
    // debugging perf regressions.
    tracesSampleRate: environment === "production" ? 0.1 : 1.0,

    // Don't send PII by default. We attach selected context via setUser/setTag.
    sendDefaultPii: false,

    // Filter out noise we don't care about.
    ignoreErrors: [
      // Connection drops from agents — happens normally with long-poll/streaming
      "ECONNRESET",
      "EPIPE",
      // Validation errors are not server bugs, they're user errors. Capture
      // them at the application layer if needed.
      "PaymentRequiredError",
    ],

    // Drop events before sending if they originate from health checks or
    // other low-value endpoints.
    beforeSend(event, hint) {
      const url = (event.request?.url ?? "").toString();
      if (url.includes("/health") || url.includes("/favicon")) return null;
      return event;
    },

    // Reduce noise from breadcrumbs we don't need.
    integrations: (defaults) =>
      defaults.filter((i) => i.name !== "Console"),
  });

  console.log("[sentry] initialized — environment:", environment, "release:", release ?? "(none)");
}

/**
 * Capture an exception with optional context. Use this for errors caught in
 * try/catch blocks where we want to log AND continue (vs. uncaught errors,
 * which the Express error handler captures automatically).
 */
export function captureException(err: unknown, context?: Record<string, unknown>): void {
  if (context) {
    Sentry.withScope((scope) => {
      for (const [k, v] of Object.entries(context)) {
        scope.setExtra(k, v);
      }
      Sentry.captureException(err);
    });
  } else {
    Sentry.captureException(err);
  }
}

/**
 * Tag the current request scope with customer/key/tool context. Called from
 * middleware so all errors emitted during this request carry the context.
 */
export function tagRequest(tags: { customer_id?: string; api_key_prefix?: string; tool_name?: string; paid_via?: string }): void {
  Sentry.getCurrentScope().setTags({
    ...(tags.customer_id ? { customer_id: tags.customer_id } : {}),
    ...(tags.api_key_prefix ? { api_key_prefix: tags.api_key_prefix } : {}),
    ...(tags.tool_name ? { tool_name: tags.tool_name } : {}),
    ...(tags.paid_via ? { paid_via: tags.paid_via } : {}),
  });
}

/**
 * Re-export the raw SDK for cases where direct access is needed (e.g., the
 * Express error handler middleware).
 */
export { Sentry };
