import { Router } from 'express';
import { BigsoSsoClient } from '../../node/SsoClient';
import type { V2ExchangeResponse } from '../../types';
import { ssoAuthMiddleware } from '../middlewares/ssoAuth';

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

        console.log('[BigsoAuthSDK] Received /exchange-v2 request with body:', req.body);
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
                console.log('[BigsoAuthSDK] Setting refresh token cookie with custom config:', options.cookieConfig);

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
            console.error('[BigsoAuthSDK] Error exchanging v2 payload:', error.message);
            res.status(401).json({ error: error.message || 'Failed to verify signed payload' });
        }
    });

    router.get('/session', async (req: import('express').Request, res: import('express').Response) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        if (options.cookieConfig) {
            console.log('[BigsoAuthSDK] session config', options.cookieConfig);
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
        // Determinar fuente del refresh token: cookie personalizada o mapa del SSO

        console.log('[BigsoAuthSDK] Received /refresh request. Cookies:', req.cookies);
        console.log('[BigsoAuthSDK] headers:', req.headers);
        const cookieConfig = options.cookieConfig;
        const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
        const cookiePath = cookieConfig?.refreshPath;
        const cookieSameSite = cookieConfig ? cookieConfig.sameSite : process.env.COOKIE_SAMESITE as 'strict' | 'lax' | 'none';

        try {
            const refreshToken = req.cookies?.[cookieConfig?.refreshName as string]

            if (!refreshToken) {
                res.status(401).json({ error: 'No refresh token available' });
                return;
            }
            const tenantId = req.headers['x-tenant-id']?.toString() || '';
            console.log('TENANT ANTES DE ENVIAR:', tenantId);
            const ssoResponse = await options.ssoClient.refreshTokens(refreshToken, tenantId);
            const maxAge = cookieConfig?.maxAge || 7 * 24 * 60 * 60 * 1000;

            if (ssoResponse.tokens?.refreshToken) {
                res.cookie(cookieConfig?.refreshName as string, ssoResponse.tokens.refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: cookieSameSite,
                    path: cookiePath,
                    maxAge: maxAge,
                    domain: cookieDomain
                });
            } else {
                console.warn('[BigsoAuthSDK] No refresh token received in refresh response, not setting cookie');
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
                console.log(`[BigsoAuthSDK] Refreshed permissions cookie for tenant ${currentTenant.id} with ${currentTenant.permissions.length} permissions`);
            } else if (cookieConfig) {
                console.warn('[BigsoAuthSDK] No permissions received in refresh response — permissions cookie NOT updated');
            }

            res.json({
                success: true,
                tokens: ssoResponse.tokens,
            });
        } catch (error: any) {
            console.error('[BigsoAuthSDK] Error refreshing tokens:', error.message);

            if (error.message?.includes('revoked') || error.message?.includes('expired') || error.message?.includes('Invalid')) {
                res.clearCookie(cookieConfig?.refreshName as string, {
                    path: cookiePath,
                    domain: cookieDomain
                });
            }
            res.status(401).json({ error: error.message || 'Failed to refresh tokens' });
        }
    });

    router.post('/logout', ssoAuthMiddleware({ ssoClient: options.ssoClient }), async (req: import('express').Request, res: import('express').Response) => {
        try {
            const accessToken = req.headers.authorization?.substring(7) || '';
            const { revokeAll = false } = req.body || {};

            await options.ssoClient.logout(accessToken, revokeAll);

            if (options.onLogout) {
                await options.onLogout(accessToken);
            }
        } catch (error: any) {
            console.warn('[BigsoAuthSDK] Failed to logout in SSO Backend.', error.message);
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
                res.status(200).json({ success: true, message: 'Logged out' });
            }
        }
    });

    return router;
}





