import { webhookCallback } from "grammy";
import { timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import type { OpenClawConfig } from "../config/config.js";
import type { RuntimeEnv } from "../runtime.js";
import { isDiagnosticsEnabled } from "../infra/diagnostic-events.js";
import { formatErrorMessage } from "../infra/errors.js";
import {
  logWebhookError,
  logWebhookProcessed,
  logWebhookReceived,
  startDiagnosticHeartbeat,
  stopDiagnosticHeartbeat,
} from "../logging/diagnostic.js";
import { defaultRuntime } from "../runtime.js";
import { resolveTelegramAllowedUpdates } from "./allowed-updates.js";
import { withTelegramApiErrorLogging } from "./api-logging.js";
import { createTelegramBot } from "./bot.js";

function requireNonEmptyWebhookSecret(secret: string | undefined): string {
  // SECURITY: Telegram webhook authenticity relies on the X-Telegram-Bot-Api-Secret-Token header.
  // If we allow an undefined/empty secret, depending on library behavior, the webhook endpoint may
  // accept unauthenticated requests (AuthBypass). Fail closed to ensure authenticity is always enforced.
  const normalized = typeof secret === "string" ? secret.trim() : "";
  if (!normalized) {
    throw new Error(
      "Telegram webhook secret is required but was not configured. Refusing to start an unauthenticated webhook endpoint.",
    );
  }
  // Telegram's secret_token is documented as max 256 characters; enforce to avoid misconfiguration.
  if (normalized.length > 256) {
    throw new Error(
      `Telegram webhook secret is too long (${normalized.length}). Must be 1..256 characters.`,
    );
  }
  return normalized;
}

function safeConstantTimeEquals(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
// 🔒 VOTAL.AI Security Fix: Webhook authenticity may be disabled when secret token is not configured [CWE-306] - CRITICAL

  if (aBuf.length !== bBuf.length) {
    // SECURITY: avoid leaking length information via early return; still perform a timingSafeEqual.
    const max = Math.max(aBuf.length, bBuf.length, 1);
    const aPad = Buffer.alloc(max);
    const bPad = Buffer.alloc(max);
    aBuf.copy(aPad);
    bBuf.copy(bPad);
    timingSafeEqual(aPad, bPad);
    return false;
  }

  // timingSafeEqual throws if lengths differ; we handled that above.
  return timingSafeEqual(aBuf, bBuf);
}

function getTelegramSecretHeaderValue(req: import("node:http").IncomingMessage): string | undefined {
  // Node normalizes headers to lowercase keys.
  const header = req.headers["x-telegram-bot-api-secret-token"];
  if (typeof header === "string") return header;
  if (Array.isArray(header)) return header[0];
  return undefined;
}

export async function startTelegramWebhook(opts: {
  token: string;
  accountId?: string;
  config?: OpenClawConfig;
  path?: string;
  port?: number;
  host?: string;
  secret?: string;
  runtime?: RuntimeEnv;
  fetch?: typeof fetch;
  abortSignal?: AbortSignal;
  healthPath?: string;
  publicUrl?: string;
}) {
  const path = opts.path ?? "/telegram-webhook";
  const healthPath = opts.healthPath ?? "/healthz";
  const port = opts.port ?? 8787;
  const host = opts.host ?? "0.0.0.0";
  const runtime = opts.runtime ?? defaultRuntime;
  const diagnosticsEnabled = isDiagnosticsEnabled(opts.config);

  // SECURITY: Require a configured secret token to prevent unauthenticated webhook requests.
  const secret = requireNonEmptyWebhookSecret(opts.secret);

  const bot = createTelegramBot({
    token: opts.token,
    runtime,
    proxyFetch: opts.fetch,
    config: opts.config,
    accountId: opts.accountId,
  });

  const handler = webhookCallback(bot, "http", {
    // Still pass to grammy so it can validate too (defense in depth).
    secretToken: secret,
  });

  if (diagnosticsEnabled) {
    startDiagnosticHeartbeat();
  }

  const server = createServer((req, res) => {
    if (req.url === healthPath) {
      res.writeHead(200);
      res.end("ok");
      return;
    }
    if (req.url !== path || req.method !== "POST") {
      res.writeHead(404);
      res.end();
      return;
    }

    // SECURITY: Enforce Telegram's secret token header ourselves so that even if upstream handler
    // behavior changes (or is misconfigured), we do not accept unauthenticated payloads.
    const provided = getTelegramSecretHeaderValue(req);
    if (!provided || !safeConstantTimeEquals(provided, secret)) {
      // Use 401 without revealing details. (Telegram will retry if misconfigured.)
      res.writeHead(401);
      res.end();
      return;
    }

    const startTime = Date.now();
    if (diagnosticsEnabled) {
      logWebhookReceived({ channel: "telegram", updateType: "telegram-post" });
    }
    const handled = handler(req, res);
    if (handled && typeof (handled as Promise<unknown>).catch === "function") {
      void (handled as Promise<unknown>)
        .then(() => {
          if (diagnosticsEnabled) {
            logWebhookProcessed({
              channel: "telegram",
              updateType: "telegram-post",
              durationMs: Date.now() - startTime,
            });
          }
        })
        .catch((err) => {
          const errMsg = formatErrorMessage(err);
          if (diagnosticsEnabled) {
            logWebhookError({
              channel: "telegram",
              updateType: "telegram-post",
              error: errMsg,
            });
          }
          runtime.log?.(`webhook handler failed: ${errMsg}`);
          if (!res.headersSent) {
            res.writeHead(500);
          }
          res.end();
        });
    }
  });

  const publicUrl =
    opts.publicUrl ?? `http://${host === "0.0.0.0" ? "localhost" : host}:${port}${path}`;

  await withTelegramApiErrorLogging({
    operation: "setWebhook",
    runtime,
    fn: () =>
      bot.api.setWebhook(publicUrl, {
        // Must match the secret enforced above.
        secret_token: secret,
        allowed_updates: resolveTelegramAllowedUpdates(),
      }),
  });

  await new Promise<void>((resolve) => server.listen(port, host, resolve));
  runtime.log?.(`webhook listening on ${publicUrl}`);

  const shutdown = () => {
    server.close();
    void bot.stop();
    if (diagnosticsEnabled) {
      stopDiagnosticHeartbeat();
    }
  };
  if (opts.abortSignal) {
    opts.abortSignal.addEventListener("abort", shutdown, { once: true });
  }

  return { server, bot, stop: shutdown };
}