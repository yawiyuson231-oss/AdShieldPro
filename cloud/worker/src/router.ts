import type { AppConfig, Env } from './env';
import { ApiError, badRequest, corsHeaders, errorResponse, hashIp, json, notFound } from './http';
import type { AuthedUser } from './security/auth';
import { resolveUser, verifySupabaseJwt } from './security/auth';
import { RATE_LIMITS, enforceRateLimit, type RateLimitRule } from './security/ratelimit';
import { recordApiUsage } from './repo/usage';
import { storageFor, type StorageProvider } from './storage/provider';

export interface Ctx {
  req: Request;
  url: URL;
  env: Env;
  config: AppConfig;
  params: Record<string, string>;
  query: URLSearchParams;
  user: AuthedUser | null;
  ipHash: string;
  userAgent: string;
  requestId: string;
  storage: () => StorageProvider;
}

export type Handler = (ctx: Ctx) => Promise<Response> | Response;

export interface RouteDefinition {
  method: string;
  path: string;
  handler: Handler;
  /** requires a verified Supabase access token + provisioned profile */
  auth?: boolean;
  rateLimit?: RateLimitRule;
  summary?: string;
}

interface CompiledRoute extends RouteDefinition {
  segments: string[];
}

export class Router {
  private readonly routes: CompiledRoute[] = [];

  add(definition: RouteDefinition): this {
    this.routes.push({ ...definition, segments: definition.path.split('/').filter(Boolean) });
    return this;
  }

  addAll(definitions: RouteDefinition[]): this {
    for (const definition of definitions) this.add(definition);
    return this;
  }

  /** Exact-then-parameter matching, with a stable preference for literal segments. */
  match(method: string, pathname: string): { route: CompiledRoute; params: Record<string, string> } | null {
    const segments = pathname.split('/').filter(Boolean);
    let best: { route: CompiledRoute; params: Record<string, string>; literalScore: number } | null = null;

    for (const route of this.routes) {
      if (route.method !== method && !(method === 'HEAD' && route.method === 'GET')) continue;
      if (route.segments.length !== segments.length) continue;
      const params: Record<string, string> = {};
      let literalScore = 0;
      let matched = true;
      for (let i = 0; i < route.segments.length; i += 1) {
        const pattern = route.segments[i];
        if (pattern.startsWith(':')) {
          params[pattern.slice(1)] = decodeURIComponent(segments[i]);
        } else if (pattern.toLowerCase() === segments[i].toLowerCase()) {
          literalScore += 1;
        } else {
          matched = false;
          break;
        }
      }
      if (!matched) continue;
      if (!best || literalScore > best.literalScore) best = { route, params, literalScore };
    }
    return best ? { route: best.route, params: best.params } : null;
  }

  get definitions(): readonly RouteDefinition[] {
    return this.routes;
  }
}

export async function dispatch(router: Router, request: Request, env: Env, config: AppConfig): Promise<Response> {
  const url = new URL(request.url);
  const cors = corsHeaders(config, request);
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const match = router.match(request.method, url.pathname);
  if (!match) {
    const error = notFound(`No route for ${request.method} ${url.pathname}`, 'route_not_found');
    return errorResponse(error, cors, requestId);
  }

  const ipHash = await hashIp(request, env.SERVER_SECRET ?? 'unset-secret');
  const userAgent = request.headers.get('User-Agent') ?? '';
  let user: AuthedUser | null = null;
  let storage: StorageProvider | null = null;

  try {
    if (match.route.rateLimit) {
      await enforceRateLimit(env, match.route.rateLimit, `${ipHash}:${match.route.path}`);
    }
    if (match.route.auth) {
      await enforceRateLimit(env, { ...RATE_LIMITS.general, limit: config.rateLimitGeneralPerMinute }, ipHash);
      const authorization = request.headers.get('Authorization') ?? '';
      const token = authorization.toLowerCase().startsWith('bearer ') ? authorization.slice(7).trim() : '';
      if (!token) throw new ApiError(401, 'unauthorized', 'Missing bearer access token');
      const claims = await verifySupabaseJwt(env, token);
      user = await resolveUser(env, config, claims);
      if (user.status !== 'active') {
        throw new ApiError(403, 'account_suspended', 'This account is suspended');
      }
    }

    const ctx: Ctx = {
      req: request,
      url,
      env,
      config,
      params: match.params,
      query: url.searchParams,
      user,
      ipHash,
      userAgent,
      requestId,
      storage: () => {
        if (!storage) storage = storageFor(env, config);
        return storage;
      },
    };

    const response = await match.route.handler(ctx);
    const headers = new Headers(response.headers);
    for (const [key, value] of Object.entries(cors)) headers.set(key, value);
    headers.set('X-Request-Id', requestId);
    headers.set('X-Response-Time', `${Date.now() - startedAt}ms`);

    // Server-Timing style visibility into the free-tier budget for the client dashboards.
    if (user) {
      try {
        await recordApiUsage(env, user.id, 0, 0);
      } catch {
        // quota telemetry must never fail a request
      }
    }
    return new Response(response.body, { status: response.status, headers });
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(error, cors, requestId);
    }
    const err = error as Error & { code?: string; status?: number };
    if (err?.code === 'unsupported_file_type' || err?.status === 415) {
      return errorResponse(new ApiError(415, err.code ?? 'unsupported_file_type', err.message), cors, requestId);
    }
    console.error('unhandled_error', requestId, err?.message, err?.stack);
    return errorResponse(
      new ApiError(500, 'internal_error', 'Unexpected server error. The problem was logged.'),
      cors,
      requestId
    );
  }
}

export function assertUser(ctx: Ctx): AuthedUser {
  if (!ctx.user) throw badRequest('This endpoint requires authentication', 'unauthorized');
  return ctx.user;
}

export const ok = (body: unknown) => json(body, 200);
