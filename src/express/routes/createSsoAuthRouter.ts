import { Router } from 'express';
import { BigsoSsoClient } from '../../node/SsoClient';
import type { V2ExchangeResponse } from '../../types';
import { SdkLogger } from '../../utils/logger';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

const logger = new SdkLogger('AuthSDK');

// ── Refresh serialization ───────────────────────────────────────────────────
// Prevents race conditions when multiple tabs send /refresh simultaneously.
// If a refresh is already in flight for the same refresh token, subsequent
// requests wait for the result instead of hitting the IDP Core again.
const activeRefreshes = new Map<string, Promise<any>>();

function getRefreshKey(token: string): string {
    // Use first 20 chars of token as key (sufficiently unique, no full token in memory)
    return token.substring(0, 20);
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
}

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
}


function serializePermissions(permissions: any[]): string {
    return permissions
        .map(p => `${p.resource}:${p.action}`)
        .join(",");
}

export function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router {
    const router = Router();

    router.post('/exchange', async (req: import('express').Request, res: import('express').Response) => {

        logger.info('Received /exchange-v2 request', { body: req.body });
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

            // Si hay cookieConfig personalizada, establecer cookie propia de la app
            if (options.cookieConfig) {
                logger.info('Setting refresh token cookie with custom config', { config: options.cookieConfig });

                const cookieConfig = options.cookieConfig;

                res.cookie(cookieConfig.sessionName, ssoResponse.tokens.jti, {
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

            if (options.onLoginSuccess) {
                await options.onLoginSuccess(ssoResponse);
            }
            delete (ssoResponse as any).tokens.refreshToken;
            res.json(ssoResponse);
        } catch (error: any) {
            logger.error('Error exchanging v2 payload', { message: error.message });
            res.status(401).json({ error: error.message || 'Failed to verify signed payload' });
        }
    });

    router.get('/session', async (req: import('express').Request, res: import('express').Response) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        if (options.cookieConfig) {
            logger.info('Session request', { config: options.cookieConfig });
            const cookieConfig = options.cookieConfig;
            const sessionId = req.cookies[cookieConfig.sessionName] as string
            const ssoclientOptions = options.ssoClient.getClientOptions();
            const ssoSession = await options.ssoClient.session(sessionId, ssoclientOptions.appId);
            res.json({
                success: true,
                ...ssoSession
            });
        }
    });

    router.post('/refresh', async (req: import('express').Request, res: import('express').Response) => {
        const cookieConfig = options.cookieConfig;
        const refreshName = cookieConfig?.refreshName;
        const incomingToken = req.cookies?.[refreshName as string];
        logger.info('Received /refresh request', {
            refreshName,
            hasCookie: !!incomingToken,
            tokenPrefix: incomingToken ? incomingToken.substring(0, 20) : null,
            tenantId: req.headers['x-tenant-id'],
        });
        const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
        const cookiePath = cookieConfig?.refreshPath;
        const cookieSameSite = cookieConfig ? cookieConfig.sameSite : process.env.COOKIE_SAMESITE as 'strict' | 'lax' | 'none';

        try {
            const refreshToken = req.cookies?.[cookieConfig?.refreshName as string]

            if (!refreshToken) {
                logger.warn('No refresh token in cookies', { refreshName });
                res.status(401).json({ error: 'No refresh token available' });
                return;
            }
            let tenantId = req.headers['x-tenant-id']?.toString() || undefined;

            // Fallback: extraer tenantId del refresh token JWT si el header está vacío
            if (!tenantId) {
                try {
                    const payload = JSON.parse(Buffer.from(refreshToken.split('.')[1], 'base64').toString());
                    tenantId = payload['https://bigso.org/tenant_id'] || payload['https://bigso.co/tenant_id'] || payload.tenantId || '';
                    if (tenantId) {
                        logger.info('Recovered tenantId from refresh token JWT', { tenantId });
                    }
                } catch (e) {
                    logger.warn('Could not parse tenantId from refresh token', { error: (e as Error).message });
                }
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
                logger.info('Refresh already in flight, waiting for result', { refreshKey });
            }

            const ssoResponse = await refreshPromise;
            const maxAge = cookieConfig?.maxAge || 7 * 24 * 60 * 60 * 1000;

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
                logger.info('Cookie updated after refresh', {
                    refreshName,
                    oldTokenPrefix: refreshToken.substring(0, 20),
                    newTokenPrefix: newToken.substring(0, 20),
                });
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

            res.json({
                success: true,
                tokens: ssoResponse.tokens,
            });
        } catch (error: any) {
            logger.error('Error refreshing tokens', { message: error.message });

            // Clear cookie on any authentication error to prevent crash loops
            const isAuthError = error.message?.includes('revoked') ||
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
                logger.info('Cleared invalid refresh token cookie', { refreshName, reason: error.message });
            }
            res.status(401).json({ error: error.message || 'Failed to refresh tokens' });
        }
    });

    router.post('/tenant-context', async (req: import('express').Request, res: import('express').Response) => {
        const accessToken = req.headers.authorization?.startsWith('Bearer ')
            ? req.headers.authorization.substring(7)
            : '';
        const tenantId = typeof req.body?.tenantId === 'string' ? req.body.tenantId : '';
        if (!accessToken || !tenantId || !options.cookieConfig) {
            res.status(400).json({ error: 'invalid_tenant_switch_request' });
            return;
        }

        const verifier = randomBytes(32).toString('base64url');
        const challenge = createHash('sha256').update(verifier).digest('base64url');
        try {
            const authorization = await options.ssoClient.authorizeTenant({
                accessToken,
                tenantId,
                redirectUri: options.tenantSwitchRedirectUri ?? `${options.frontendUrl.replace(/\/$/, '')}/launch`,
                codeChallenge: challenge,
                state: randomUUID(),
            });
            const session = await options.ssoClient.exchangeCode(authorization.code, verifier);
            const cookie = options.cookieConfig;
            const base = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: cookie.sameSite, maxAge: cookie.maxAge, domain: cookie.domain } as const;
            res.cookie(cookie.sessionName, session.tokens.jti, { ...base, path: cookie.sessionPath });
            res.cookie(cookie.refreshName, session.tokens.refreshToken, { ...base, path: cookie.refreshPath });
            res.cookie(cookie.permissionName, serializePermissions(session.currentTenant.permissions), { ...base, path: cookie.permissionPath });
            delete (session as any).tokens.refreshToken;
            res.status(200).json(session);
        } catch (error: any) {
            const cookie = options.cookieConfig;
            for (const [name, path] of [[cookie.sessionName, cookie.sessionPath], [cookie.refreshName, cookie.refreshPath], [cookie.permissionName, cookie.permissionPath]] as const) {
                res.clearCookie(name, { domain: cookie.domain, path });
            }
            logger.warn('Tenant session replacement failed', { message: error.message });
            res.status(401).json({ error: 'tenant_switch_failed' });
        }
    });

    router.post('/logout', async (req: import('express').Request, res: import('express').Response) => {
        const accessToken = req.headers.authorization?.startsWith('Bearer ')
            ? req.headers.authorization.substring(7)
            : '';

        const scope = req.body?.scope ?? (req.body?.revokeAll ? 'global' : 'application');
        if (scope !== 'application' && scope !== 'global') {
            res.status(400).json({ error: 'unsupported_logout_scope' });
            return;
        }

        let revocationSucceeded = true;
        try {
            if (accessToken) {
                // Only attempt SSO-core revocation when we actually have a token
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
            logger.warn('Failed to logout in SSO Backend', { message: error.message });
            // Continue — always clear cookies and respond regardless of sso-core error
        } finally {
            // Always clear cookies no matter what happened above
            const cookieConfig = options.cookieConfig;
            const clearOpts = cookieConfig
                ? { domain: cookieConfig.domain, path: '/' }
                : {};

            for (const cookieName of [cookieConfig?.sessionName, cookieConfig?.refreshName, cookieConfig?.permissionName]) {
                if (cookieName) {
                    res.clearCookie(cookieName, clearOpts);
                }
            }

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


