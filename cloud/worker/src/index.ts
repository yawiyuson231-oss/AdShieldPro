import type { Env } from './env';
import { loadConfig } from './env';
import { Router, dispatch } from './router';
import { accountRoutes } from './routes/account';
import { fileRoutes } from './routes/files';
import { transferRoutes } from './routes/transfer';
import { sharingRoutes } from './routes/sharing';
import { backupRoutes } from './routes/backups';
import { json } from './http';
import { purgeExpiredSessions } from './repo/uploads';
import { pruneRateLimitWindows } from './security/ratelimit';
import { storageFor } from './storage/provider';

/**
 * CyberShield Cloud — Cloudflare Worker entry point.
 *
 * Runs entirely on the Workers Free plan (100k requests/day) with D1 Free metadata and a
 * free-tier object store (R2 10 GB with a payment method on file, or Supabase Storage 1 GB
 * with no card). No code path here can enable a paid plan.
 */

const router: Router = new Router()
  .addAll(accountRoutes)
  .addAll(fileRoutes)
  .addAll(transferRoutes)
  .addAll(sharingRoutes)
  .addAll(backupRoutes)
  .add({
    method: 'GET',
    path: '/',
    handler: (ctx) =>
      json({
        name: 'CyberShield Cloud',
        docs: '/health, /v1/meta',
        routes: router.definitions
          .filter((route) => route.summary)
          .map((route) => ({
            method: route.method,
            path: route.path,
            auth: Boolean(route.auth),
            summary: route.summary,
          }))
          .sort((a, b) => a.path.localeCompare(b.path)),
        environment: ctx.config.environment,
        paidFeaturesEnabled: false,
      }),
  })
  .add({
    method: 'GET',
    path: '/v1/openapi.json',
    handler: (ctx) =>
      json({
        openapi: '3.1.0',
        info: { title: 'CyberShield Cloud API', version: '1.0.0' },
        servers: [{ url: ctx.url.origin }],
        paths: Object.fromEntries(
          router.definitions.map((route) => [
            route.path,
            {
              [route.method.toLowerCase()]: {
                summary: route.summary ?? '',
                security: route.auth ? [{ bearerAuth: [] }] : [],
                responses: { '200': { description: 'Success' } },
              },
            },
          ])
        ),
        components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'Supabase JWT' } } },
      }),
  });

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const config = loadConfig(env);
    return dispatch(router, request, env, config);
  },

  /** Cron trigger: abort stale upload sessions and prune rate-limit windows. */
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const config = loadConfig(env);
    ctx.waitUntil(
      (async () => {
        try {
          await purgeExpiredSessions(env, storageFor(env, config));
          await pruneRateLimitWindows(env);
        } catch (error) {
          console.error('scheduled_maintenance_failed', (error as Error)?.message);
        }
      })()
    );
  },
};
