import { Router } from 'express';
import { BigsoSsoClient } from '../../node/SsoClient';
import type { V2ExchangeResponse } from '../../types';
import { SdkLogger } from '../../utils/logger';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { projectPublicAuthResponse } from '../publicAuthResponse';
import {
    buildSessionCookieOptions,
    clearLegacyCookies,
    isHostOnlyConfig,
    resolveSessionCookieNames,
    type EffectiveCookieConfig,
} from '../cookies/hostOnlyCookies';
import { generateCsrfSecret, generateCsrfToken } from '../middlewares/csrfGuard';

const logger = new SdkLogger('AuthSDK');

// ── Refresh serialization ───────────────────────────────────────────────────
// Prevents race conditions when multiple tabs send /refresh simultaneously.
// If a refresh is already in flight for the same refresh token, subsequent
// requests wait for the result instead of hitting the IDP Core again.
const activeRefreshes = new Map<string, Promise<any>>();

function getRefreshKey(token: string): string {
    return createHash('sha256').update(token).digest('base64url');
}

export interface CookieConfig {
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
    legacyCookies?: { name: string; domain?: string; path?: string }[];
}

export type CookieConfigWithOptionalSameSite = Omit<CookieConfig, 'sameSite'> & { sameSite?: CookieConfig['sameSite'] };

export interface CreateSsoAuthRouterOptions {
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


function serializePermissions(permissions: any[]): string {
    return permissions
        .map(p => `${p.resource}:${p.action}`)
        .join(",");
}

export function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router {
    const router = Router();

    if (options.hostOnlyCookies && !options.appSlug) {
        throw new Error('appSlug is required when hostOnlyCookies is enabled');
    }

    const effectiveCookieConfig: EffectiveCookieConfig | undefined = options.cookieConfig
        ? options.hostOnlyCookies && options.appSlug
            ? { ...options.cookieConfig, hostOnly: true, appSlug: options.appSlug }
            : options.cookieConfig
        : undefined;

    const sessionCookieNames = effectiveCookieConfig
        ? resolveSessionCookieNames(effectiveCookieConfig)
        : [];

    const csrfSecret = options.csrfSecret ?? generateCsrfSecret();

    function deriveCsrfToken(sessionHandle: string): string {
        return generateCsrfToken(sessionHandle, csrfSecret);
    }

    function getSessionHandleFromCookies(req: import('express').Request): string | undefined {
        if (!effectiveCookieConfig || !req.cookies) return undefined;
        for (const name of sessionCookieNames) {
            const value = req.cookies[name] as string | undefined;
            if (value) return value;
        }
        return undefined;
    }

    function setHostOnlySessionCookie(res: import('express').Response, sessionHandle: string): void {
        if (!effectiveCookieConfig || !isHostOnlyConfig(effectiveCookieConfig)) return;
        const { name, options } = buildSessionCookieOptions(effectiveCookieConfig);
        res.cookie(name, sessionHandle, options);
    }

    function clearAuthCookies(res: import('express').Response): void {
        if (!effectiveCookieConfig) return;

        if (isHostOnlyConfig(effectiveCookieConfig)) {
            const { name, options } = buildSessionCookieOptions(effectiveCookieConfig);
            res.clearCookie(name, { path: options.path });
            clearLegacyCookies(res, effectiveCookieConfig.legacyCookies ?? []);
        } else {
            const cookieConfig = effectiveCookieConfig;
            res.clearCookie(cookieConfig.sessionName, { domain: cookieConfig.domain, path: cookieConfig.sessionPath });
            res.clearCookie(cookieConfig.refreshName, { domain: cookieConfig.domain, path: cookieConfig.refreshPath });
            res.clearCookie(cookieConfig.permissionName, { domain: cookieConfig.domain, path: cookieConfig.permissionPath });
        }
    }

    router.post('/exchange', async (req: import('express').Request, res: import('express').Response) => {

        logger.info('Received authentication exchange request');
        try {
            const { payload, codeVerifier: codeVerifierFromBody } = req.body;
            if (!payload) {
                res.status(400).json({ error: 'Signed payload is required' });
                return;
            }

            const verified = await options.ssoClient.verifySignedPayload(payload, options.frontendUrl);
            if (!verified.code) {
                res.status(400).json({ error: 'No authorization code found in payload' });
                return;
            }

            const verifier = codeVerifierFromBody || (verified as any).code_verifier;
            if (!verifier) {
                res.status(400).json({ error: 'codeVerifier is required for PKCE exchange' });
                return;
            }

            const ssoResponse = await options.ssoClient.exchangeCode(verified.code, verifier);

            const opaqueSessionHandle = ssoResponse.sessionId ?? ssoResponse.tokens.jti;

            if (effectiveCookieConfig && opaqueSessionHandle) {
                if (isHostOnlyConfig(effectiveCookieConfig)) {
                    logger.info('Establishing host-only application session cookie');
                    setHostOnlySessionCookie(res, opaqueSessionHandle);
                    clearLegacyCookies(res, effectiveCookieConfig.legacyCookies ?? []);
                } else {
                    logger.info('Establishing legacy application session cookies');
                    const cookieConfig = effectiveCookieConfig;
                    res.cookie(cookieConfig.sessionName, opaqueSessionHandle, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: cookieConfig.sameSite,
                        path: cookieConfig.sessionPath,
                        maxAge: cookieConfig.maxAge,
                        domain: cookieConfig.domain
                    });

                    res.cookie(cookieConfig.refreshName, ssoResponse.tokens.refreshToken, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: cookieConfig.sameSite,
                        path: cookieConfig.refreshPath,
                        maxAge: cookieConfig.maxAge,
                        domain: cookieConfig.domain
                    });

                    res.cookie(cookieConfig.permissionName, serializePermissions(ssoResponse.currentTenant.permissions), {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: cookieConfig.sameSite,
                        path: cookieConfig.permissionPath,
                        maxAge: cookieConfig.maxAge,
                        domain: cookieConfig.domain
                    });
                }
            }

            if (options.onLoginSuccess) {
                await options.onLoginSuccess(ssoResponse);
            }
            res.json(projectPublicAuthResponse({
                ...ssoResponse,
                ...(effectiveCookieConfig && isHostOnlyConfig(effectiveCookieConfig) && opaqueSessionHandle
                    ? { csrfToken: deriveCsrfToken(opaqueSessionHandle) }
                    : {}),
            }));
        } catch (error: any) {
            logger.error('Authentication exchange failed', { errorType: error?.name ?? 'UnknownError' });
            res.status(401).json({ error: 'exchange_failed' });
        }
    });

    router.get('/session', async (req: import('express').Request, res: import('express').Response) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        if (effectiveCookieConfig) {
            logger.info('Resolving application session');
            const sessionHandle = getSessionHandleFromCookies(req);
            if (!sessionHandle) {
                res.status(401).json({ error: 'session_required' });
                return;
            }
            const ssoclientOptions = options.ssoClient.getClientOptions();
            const ssoSession = await options.ssoClient.session(sessionHandle, ssoclientOptions.appId);
            res.json(projectPublicAuthResponse({
                success: true,
                ...ssoSession,
                ...(isHostOnlyConfig(effectiveCookieConfig)
                    ? { csrfToken: deriveCsrfToken(sessionHandle) }
                    : {}),
            }));
        }
    });

    router.post('/refresh', async (req: import('express').Request, res: import('express').Response) => {
        // In the host-only profile the browser no longer stores a refresh cookie. The BFF
        // performs server-side refresh, so this route is a no-op that returns the public session.
        if (effectiveCookieConfig && isHostOnlyConfig(effectiveCookieConfig)) {
            logger.info('Host-only refresh route invoked');
            const sessionHandle = getSessionHandleFromCookies(req);
            if (!sessionHandle) {
                res.status(401).json({ error: 'session_required' });
                return;
            }
            const ssoclientOptions = options.ssoClient.getClientOptions();
            const ssoSession = await options.ssoClient.session(sessionHandle, ssoclientOptions.appId);
            res.json(projectPublicAuthResponse({
                success: true,
                ...ssoSession,
                csrfToken: deriveCsrfToken(sessionHandle),
            }));
            return;
        }

        const cookieConfig = options.cookieConfig;
        const refreshName = cookieConfig?.refreshName;
        const incomingToken = req.cookies?.[refreshName as string];
        logger.info('Received refresh request', {
            hasSessionCredential: !!incomingToken,
        });
        const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
        const cookiePath = cookieConfig?.refreshPath;
        const cookieSameSite = cookieConfig ? cookieConfig.sameSite : process.env.COOKIE_SAMESITE as 'strict' | 'lax' | 'none';

        try {
            const refreshToken = req.cookies?.[cookieConfig?.refreshName as string]

            if (!refreshToken) {
                logger.warn('No refresh credential available');
                res.status(401).json({ error: 'No refresh token available' });
                return;
            }
            let tenantId: string | undefined;

            // The tenant context comes only from the server-held refresh credential.
            // An incoming browser header is not an identity source.
            try {
                const payload = JSON.parse(Buffer.from(refreshToken.split('.')[1], 'base64').toString());
                tenantId = payload['https://bigso.org/tenant_id'] || payload['https://bigso.co/tenant_id'] || payload.tenantId || '';
                if (tenantId) {
                    logger.info('Recovered tenant context from refresh credential');
                }
            } catch {
                logger.warn('Could not resolve tenant context from refresh credential');
            }

            logger.info('Forwarding refresh to IDP', { tenantId: tenantId || '(empty)' });

            // ── Serialize refresh requests with the same token ───────────────
            const refreshKey = getRefreshKey(refreshToken);
            let refreshPromise = activeRefreshes.get(refreshKey);

            if (!refreshPromise) {
                refreshPromise = options.ssoClient.refreshTokens(refreshToken, tenantId as string)
                    .catch((err: any) => {
                        // Remove from active map on error so subsequent retries can proceed
                        activeRefreshes.delete(refreshKey);
                        throw err;
                    });
                activeRefreshes.set(refreshKey, refreshPromise);

                // Clean up on success only (errors are handled above)
                refreshPromise.then(() => {
                    activeRefreshes.delete(refreshKey);
                }).catch(() => {
                    // Already handled above; this catch prevents unhandled rejection
                });
            } else {
                logger.info('Refresh already in flight, waiting for result');
            }

            const ssoResponse = await refreshPromise;
            const maxAge = cookieConfig?.maxAge || 7 * 24 * 60 * 60 * 1000;

            const opaqueSessionHandle = ssoResponse.sessionId ?? ssoResponse.tokens?.jti;
            if (cookieConfig && opaqueSessionHandle) {
                res.cookie(cookieConfig.sessionName, opaqueSessionHandle, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: cookieSameSite,
                    path: cookieConfig.sessionPath,
                    maxAge,
                    domain: cookieDomain
                });
                logger.info('Session cookie rotated after refresh');
            }

            if (ssoResponse.tokens?.refreshToken) {
                const newToken = ssoResponse.tokens.refreshToken;
                res.cookie(cookieConfig?.refreshName as string, newToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: cookieSameSite,
                    path: cookiePath,
                    maxAge: maxAge,
                    domain: cookieDomain
                });
                logger.info('Refresh credential cookie rotated');
            } else {
                logger.warn('No refresh token received in refresh response, not setting cookie');
            }

            // ── Re-write permissions cookie after refresh ─────────────────────────
            // The RBAC middleware reads permissions from this cookie on every request.
            // If we skip updating it here, it becomes stale or expires independently,
            // causing 403s even when the user has valid permissions in sso-core.
            const currentTenant = ssoResponse.currentTenant;
            if (cookieConfig && currentTenant && currentTenant.permissions?.length > 0) {
                res.cookie(cookieConfig.permissionName, serializePermissions(currentTenant.permissions), {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: cookieSameSite,
                    path: cookieConfig.permissionPath,
                    maxAge: maxAge,
                    domain: cookieDomain
                });
                logger.info('Refreshed permissions cookie', { tenantId: currentTenant.id, count: currentTenant.permissions.length });
            } else if (cookieConfig) {
                logger.warn('No permissions received in refresh response — permissions cookie NOT updated');
            }

            res.json(projectPublicAuthResponse(ssoResponse));
        } catch (error: any) {
            logger.error('Token refresh failed', { errorType: error?.name ?? 'UnknownError' });

            // Clear cookie on any authentication error to prevent crash loops
            const isAuthError = error?.status === 401 || error?.status === 403 ||
                error.message?.includes('revoked') ||
                error.message?.includes('expired') ||
                error.message?.includes('Invalid') ||
                error.message?.includes('not recognized') ||
                error.message?.includes('Token not found') ||
                error.message?.includes('reuse detected');

            if (isAuthError) {
                res.clearCookie(cookieConfig?.refreshName as string, {
                    path: cookiePath,
                    domain: cookieDomain
                });
                logger.info('Cleared invalid refresh credential cookie');
            }
            res.status(401).json({ error: 'refresh_failed' });
        }
    });

    router.post('/tenant-context', async (req: import('express').Request, res: import('express').Response) => {
        let accessToken = req.headers.authorization?.startsWith('Bearer ')
            ? req.headers.authorization.substring(7)
            : '';
        const tenantId = typeof req.body?.tenantId === 'string' ? req.body.tenantId : '';
        if (!tenantId || !effectiveCookieConfig) {
            res.status(400).json({ error: 'invalid_tenant_switch_request' });
            return;
        }

        const verifier = randomBytes(32).toString('base64url');
        const challenge = createHash('sha256').update(verifier).digest('base64url');
        try {
            if (!accessToken) {
                const sessionHandle = getSessionHandleFromCookies(req);
                if (!sessionHandle) {
                    res.status(401).json({ error: 'tenant_switch_session_required' });
                    return;
                }
                const current = await options.ssoClient.session(
                    sessionHandle,
                    options.ssoClient.getClientOptions().appId,
                );
                accessToken = current?.tokens?.accessToken ?? current?.accessToken ?? '';
                if (!accessToken) {
                    res.status(401).json({ error: 'tenant_switch_session_required' });
                    return;
                }
            }
            const authorization = await options.ssoClient.authorizeTenant({
                accessToken,
                tenantId,
                redirectUri: options.tenantSwitchRedirectUri ?? `${options.frontendUrl.replace(/\/$/, '')}/launch`,
                codeChallenge: challenge,
                state: randomUUID(),
            });
            const session = await options.ssoClient.exchangeCode(authorization.code, verifier);
            const opaqueSessionHandle = session.sessionId ?? session.tokens.jti;

            if (isHostOnlyConfig(effectiveCookieConfig) && opaqueSessionHandle) {
                setHostOnlySessionCookie(res, opaqueSessionHandle);
                clearLegacyCookies(res, effectiveCookieConfig.legacyCookies ?? []);
            } else {
                const cookie = effectiveCookieConfig;
                const base = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: cookie.sameSite, maxAge: cookie.maxAge, domain: cookie.domain } as const;
                res.cookie(cookie.sessionName, opaqueSessionHandle, { ...base, path: cookie.sessionPath });
                res.cookie(cookie.refreshName, session.tokens.refreshToken, { ...base, path: cookie.refreshPath });
                res.cookie(cookie.permissionName, serializePermissions(session.currentTenant.permissions), { ...base, path: cookie.permissionPath });
            }

            if (options.onLoginSuccess) await options.onLoginSuccess(session);
            res.status(200).json(projectPublicAuthResponse({
                ...session,
                ...(isHostOnlyConfig(effectiveCookieConfig) && opaqueSessionHandle
                    ? { csrfToken: deriveCsrfToken(opaqueSessionHandle) }
                    : {}),
            }));
        } catch (error: any) {
            clearAuthCookies(res);
            logger.warn('Tenant session replacement failed', { errorType: error?.name ?? 'UnknownError' });
            res.status(401).json({ error: 'tenant_switch_failed' });
        }
    });

    router.post('/logout', async (req: import('express').Request, res: import('express').Response) => {
        let accessToken = req.headers.authorization?.startsWith('Bearer ')
            ? req.headers.authorization.substring(7)
            : '';

        const scope = req.body?.scope ?? (req.body?.revokeAll ? 'global' : 'application');
        if (scope !== 'application' && scope !== 'global') {
            res.status(400).json({ error: 'unsupported_logout_scope' });
            return;
        }

        let revocationSucceeded = true;
        try {
            if (!accessToken && effectiveCookieConfig) {
                const sessionHandle = getSessionHandleFromCookies(req);
                if (sessionHandle) {
                    const current = await options.ssoClient.session(
                        sessionHandle,
                        options.ssoClient.getClientOptions().appId,
                    );
                    accessToken = current?.tokens?.accessToken ?? current?.accessToken ?? '';
                }
            }

            if (accessToken) {
                // The BFF resolves the credential from its HttpOnly session when
                // the browser correctly sends no bearer token.
                await options.ssoClient.logout(accessToken, { scope });
            } else {
                logger.warn('Logout called without access token — skipping SSO-core revocation, clearing cookies anyway.');
                if (scope === 'global') revocationSucceeded = false;
            }

            if (options.onLogout) {
                await options.onLogout(accessToken);
            }
        } catch (error: any) {
            revocationSucceeded = false;
            logger.warn('Failed to logout in SSO Backend', { errorType: error?.name ?? 'UnknownError' });
            // Continue — always clear cookies and respond regardless of sso-core error
        } finally {
            // Always clear cookies no matter what happened above
            clearAuthCookies(res);

            // Always respond so the client doesn't time out
            if (!res.headersSent) {
                if (scope === 'global' && (!revocationSucceeded || !options.identityLogoutUrl)) {
                    res.status(502).json({ error: 'global_logout_unavailable' });
                    return;
                }

                if (scope === 'global') {
                    const state = randomUUID();
                    const continuation = new URL(options.identityLogoutUrl as string);
                    continuation.searchParams.set('app_id', options.ssoClient.getClientOptions().appId);
                    continuation.searchParams.set(
                        'return_uri',
                        options.logoutReturnUri ?? `${options.frontendUrl.replace(/\/$/, '')}/launch`,
                    );
                    continuation.searchParams.set('state', state);
                    continuation.searchParams.set('transition', 'bigso-overlay-v1');
                    res.status(200).json({
                        success: true,
                        scope,
                        continueUrl: continuation.toString(),
                        state,
                    });
                    return;
                }

                res.status(200).json({ success: true, scope });
            }
        }
    });

    return router;
}
