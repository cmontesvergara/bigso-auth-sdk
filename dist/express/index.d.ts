import * as express from 'express';
import { Router, Response, Request, NextFunction } from 'express';
import { BigsoSsoClient } from '../node/index.js';
import { V as V2ExchangeResponse, S as SsoJwtTenant, i as SsoTokenPayload, j as SsoUser, k as SsoTenant, A as ActiveSessionApplication } from '../types-DPeoi2iF.js';

interface CookieConfig {
    sessionName: string;
    refreshName: string;
    permissionName: string;
    domain: string;
    sessionPath: string;
    refreshPath: string;
    permissionPath: string;
    sameSite: 'strict' | 'lax' | 'none';
    maxAge: number;
    /**
     * When using the host-only profile, list every legacy cookie name (and optional domain)
     * that should be explicitly expired during migration. The router will clear both the
     * parent-domain variant (if domain is provided) and the host-only variant (no domain).
     */
    legacyCookies?: {
        name: string;
        domain?: string;
        path?: string;
    }[];
}
type CookieConfigWithOptionalSameSite = Omit<CookieConfig, 'sameSite'> & {
    sameSite?: CookieConfig['sameSite'];
};
interface CreateSsoAuthRouterOptions {
    ssoClient: BigsoSsoClient;
    frontendUrl: string;
    onLoginSuccess?: (session: V2ExchangeResponse) => void | Promise<void>;
    onLogout?: (accessToken: string) => void | Promise<void>;
    /** Top-level Identity route that owns the global SSO cookie. */
    identityLogoutUrl?: string;
    /** Exactly registered application receiver. Defaults to `${frontendUrl}/launch`. */
    logoutReturnUri?: string;
    /** Registered redirect used for application-local tenant session replacement. */
    tenantSwitchRedirectUri?: string;
    /**
     * Configuración de cookies personalizadas.
     * Si se proporciona, el router usará esta cookie en lugar de extraer
     * el nombre desde bs_cookie_name_map.
     * Esto permite que apps satélite tengan su propia cookie de refresh token.
     */
    cookieConfig?: CookieConfig;
    /**
     * When true, the router rotates to the host-only `__Host-Http-bigso-session-*`
     * cookie profile and emits the corresponding CSRF token in public responses.
     * The legacy cookie names listed in {@link CookieConfig.legacyCookies} (when using
     * the host-only profile) are cleared on every exchange/refresh/tenant-context and logout.
     */
    hostOnlyCookies?: boolean;
    /** Application slug used to derive the host-only cookie name. Required when hostOnlyCookies is true. */
    appSlug?: string;
    /** Server-only secret used to derive session-bound CSRF tokens. If omitted, a random secret is generated at startup. */
    csrfSecret?: string;
}
declare function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router;

/**
 * Canonical host-only cookie profile for BIGSO application sessions.
 *
 * Requirements:
 * - Name starts with `__Host-` so the browser enforces Secure, HttpOnly, Path=/ and no Domain.
 * - Secure is true (host-only `__Host-*` cookies are rejected over plain HTTP by modern browsers).
 * - HttpOnly so JavaScript cannot read the session handle.
 * - Path=/ so the cookie is sent to every route of the exact host.
 * - No Domain attribute so the cookie is bound to the exact middleware hostname.
 * - SameSite defaults to 'strict' and is configurable only for topologies that require lax.
 *
 * The SDK still accepts a consumer-provided `CookieConfig` for the transition window, but
 * production deployments SHOULD set `hostOnly: true` to adopt the `__Host-Http-*` profile.
 */
interface HostOnlyCookieConfig extends CookieConfigWithOptionalSameSite {
    /** When true, emit the canonical `__Host-Http-bigso-session-<app>` cookie. */
    hostOnly: true;
    /**
     * Human-readable application slug used in the cookie name.
     * Must be kebab-case and unique per application.
     */
    appSlug: string;
    /** Optional set of legacy cookie names to clear during migration. */
    legacyCookies?: LegacyCookieDefinition[];
    /** Explicit SameSite value. Defaults to 'strict'. */
    sameSite?: 'strict' | 'lax' | 'none';
}
interface LegacyCookieDefinition {
    /** Legacy cookie name to expire. */
    name: string;
    /** Domain that was used to set the legacy cookie. Omit for host-only variants. */
    domain?: string;
    /** Path that was used to set the legacy cookie. Defaults to '/'. */
    path?: string;
}
type EffectiveCookieConfig = CookieConfigWithOptionalSameSite | HostOnlyCookieConfig;
declare function isHostOnlyConfig(config: EffectiveCookieConfig | undefined): config is HostOnlyCookieConfig;
/**
 * Builds the canonical host-only session cookie name.
 *
 * The `__Host-` prefix causes browsers to reject the cookie unless it is set with
 * Secure, HttpOnly, Path=/ and without a Domain attribute. We append a BIGSO-specific
 * namespace to avoid collisions with other frameworks.
 */
declare function hostOnlySessionName(appSlug: string): string;
/**
 * Derives the cookie options for the host-only profile.
 * `secure` is forced to true: a `__Host-*` cookie sent over HTTP would be rejected anyway.
 */
declare function hostOnlyCookieOptions(maxAge: number, sameSite?: 'strict' | 'lax' | 'none'): {
    readonly httpOnly: true;
    readonly secure: true;
    readonly sameSite: "strict" | "lax" | "none";
    readonly path: "/";
    readonly maxAge: number;
};
/**
 * Clears both known legacy cookie variants: parent-domain and host-only.
 *
 * During the migration window a single browser may hold cookies emitted under the old
 * name with the old domain AND the same name without domain (e.g. after a local change
 * or a test). We expire every known variant explicitly so the browser never has multiple
 * active cookies with the same name and ambiguous scope.
 */
declare function clearLegacyCookies(res: Response, legacyCookies: LegacyCookieDefinition[]): void;
/**
 * Builds a Set-Cookie options object compatible with the configured profile.
 *
 * For host-only configs it returns the canonical `__Host-*` options and ignores
 * any `domain`/`sessionPath` provided in the legacy CookieConfig fields.
 * For legacy configs it preserves the supplied domain/path for backward compatibility.
 */
declare function buildSessionCookieOptions(config: EffectiveCookieConfig): {
    name: string;
    options: express.CookieOptions;
};
/**
 * Returns all cookie names that could have been used for an application session.
 * Useful for BFF middleware that needs to look up either the new host-only cookie or
 * a known legacy name during the migration window.
 */
declare function resolveSessionCookieNames(config: EffectiveCookieConfig): string[];

interface SsoAuthMiddlewareOptions {
    ssoClient: BigsoSsoClient;
    /**
     * Cookie de sesión para fallback cuando no hay Authorization header.
     * Permite que window.open() y navegaciones directas funcionen sin
     * que el frontend inyecte manualmente el Bearer token.
     *
     * Si se proporciona, el middleware lee la cookie `sessionName`,
     * resuelve la sesión via SSO y extrae el accessToken.
     *
     * Accepts a plain legacy sessionName for backward compatibility, or a full
     * EffectiveCookieConfig to support the host-only profile during migration.
     */
    cookieConfig?: {
        sessionName: string;
    } | EffectiveCookieConfig;
}
declare global {
    namespace Express {
        interface Request {
            user?: {
                userId: string;
                email: string;
                firstName: string;
                lastName: string;
            };
            tenant?: SsoJwtTenant;
            tokenPayload?: SsoTokenPayload;
        }
    }
}
declare function ssoAuthMiddleware(options: SsoAuthMiddlewareOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;

interface CsrfMiddlewareOptions {
    /**
     * Function that extracts the CSRF token bound to the current application session.
     * The session handle should be read from the HttpOnly host-only session cookie.
     */
    getSessionCsrfToken: (req: Request) => string | undefined;
    /**
     * Approved origins for cookie-authenticated mutations. The request Origin header
     * must match exactly one entry (case-insensitive). In production this list is small.
     */
    allowedOrigins: string[];
    /**
     * When true, enforce Sec-Fetch-Site metadata as an additional signal.
     * Recommended for modern same-site deployments.
     */
    requireSameSiteFetch?: boolean;
    /**
     * Optional extra predicate for routes that should skip CSRF checks.
     * Safe methods (GET, HEAD, OPTIONS, TRACE) are always skipped.
     */
    skipIf?: (req: Request) => boolean;
}
/**
 * Generates a session-bound CSRF token. The value is deterministic for a given session
 * so that multiple tabs or reloads share the same token, but it is not guessable from
 * outside because it depends on a server-only session secret and the opaque handle.
 */
declare function generateCsrfToken(sessionHandle: string, sessionSecret: string): string;
/**
 * Generates a fresh random secret used by the BFF to sign/prove session-bound CSRF tokens.
 * This secret lives in server memory (or a distributed cache in multi-instance deployments)
 * and must never reach the browser.
 */
declare function generateCsrfSecret(): string;
/**
 * Express middleware that enforces Origin + CSRF token validation on state-changing
 * cookie-authenticated requests.
 *
 * Fail-closed behavior:
 * - Missing or unapproved Origin → 403 csrf_or_origin_mismatch
 * - Missing or mismatched CSRF token → 403 csrf_or_origin_mismatch
 * - Unsafe Sec-Fetch-Site (when required) → 403 csrf_or_origin_mismatch
 *
 * GET/HEAD/OPTIONS/TRACE are always allowed because they must not mutate state.
 */
interface CsrfValidationResult {
    ok: true;
}
interface CsrfValidationFailure {
    ok: false;
    reason: 'method_safe' | 'skipped' | 'origin_mismatch' | 'sec_fetch_site_mismatch' | 'missing_header' | 'token_mismatch';
}
declare function validateCsrf(req: Request, options: CsrfMiddlewareOptions): CsrfValidationResult | CsrfValidationFailure;
declare function csrfGuardMiddleware(options: CsrfMiddlewareOptions): (req: Request, res: Response, next: NextFunction) => void;

interface SsoSyncGuardOptions {
    ssoBackendUrl: string;
    isProduction?: boolean;
}
declare function ssoSyncGuardMiddleware(options: SsoSyncGuardOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;

interface PublicAuthResponse {
    success: boolean;
    expiresIn?: number;
    user?: SsoUser;
    currentTenant?: SsoTenant;
    relatedTenants?: SsoTenant[];
    activeApplications?: ActiveSessionApplication[];
    csrfToken?: string;
}
/**
 * Builds the only authentication/session shape that may cross into browser JavaScript.
 * Never spread upstream Identity responses here: new internal fields must remain private by default.
 */
declare function projectPublicAuthResponse(value: unknown): PublicAuthResponse;

interface SsoSyncRouterOptions {
    resources: any[];
    appId: string;
    ssoBackendUrl: string;
    isProduction?: boolean;
}
declare function createSsoSyncRouter(options: SsoSyncRouterOptions): Router;

interface ContextualLaunchRouterOptions {
    ssoClient: BigsoSsoClient;
    cookieConfig: Pick<CookieConfig, 'sessionName'>;
}
declare function createContextualLaunchRouter(options: ContextualLaunchRouterOptions): Router;

export { type ContextualLaunchRouterOptions, type CookieConfig, type CreateSsoAuthRouterOptions, type CsrfMiddlewareOptions, type CsrfValidationFailure, type CsrfValidationResult, type EffectiveCookieConfig, type HostOnlyCookieConfig, type LegacyCookieDefinition, type PublicAuthResponse, type SsoAuthMiddlewareOptions, type SsoSyncGuardOptions, type SsoSyncRouterOptions, buildSessionCookieOptions, clearLegacyCookies, createContextualLaunchRouter, createSsoAuthRouter, createSsoSyncRouter, csrfGuardMiddleware, generateCsrfSecret, generateCsrfToken, hostOnlyCookieOptions, hostOnlySessionName, isHostOnlyConfig, projectPublicAuthResponse, resolveSessionCookieNames, ssoAuthMiddleware, ssoSyncGuardMiddleware, validateCsrf };
