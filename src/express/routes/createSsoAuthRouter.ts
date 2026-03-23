import { Router } from 'express';
import { ssoAuthMiddleware } from '../middlewares/ssoAuth';
import type { BigsoSsoClient } from '../../node/SsoClient';
import type { SsoSessionData } from '../../types';

export interface CreateSsoAuthRouterOptions {
    ssoClient: BigsoSsoClient;
    frontendUrl: string;
    cookieName?: string;
    cookieDomain?: string;
    isProduction?: boolean;
    onLoginSuccess?: (session: SsoSessionData) => void | Promise<void>;
    onLogout?: (sessionToken: string) => void | Promise<void>;
}

export function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router {
    const router = Router();
    const cookieName = options.cookieName || 'sso_session';
    const isProduction = options.isProduction ?? process.env.NODE_ENV === 'production';

    const getCookieOptions = (customOptions: any = {}) => {
        const base = {
            httpOnly: true,
            secure: isProduction,
            sameSite: 'lax' as const,
            path: '/',
            ...customOptions
        };
        if (isProduction && options.cookieDomain) {
            base.domain = options.cookieDomain;
        }
        return base;
    };

    /**
     * POST /exchange
     * Exchange authorization code for session token from SSO
     */
    router.post('/exchange', async (req: import('express').Request, res: import('express').Response) => {
        try {
            const { code } = req.body;
            if (!code) {
                res.status(400).json({ error: "Authorization code is required" });
                return;
            }

            const ssoResponse = await options.ssoClient.exchangeCodeForToken(code);

            if (!ssoResponse.success) {
                res.status(401).json({ error: "Invalid authorization code" });
                return;
            }

            const sessionMaxAge = new Date(ssoResponse.expiresAt).getTime() - Date.now();
            const refreshMaxAge = ssoResponse.refreshExpiresAt 
                ? new Date(ssoResponse.refreshExpiresAt).getTime() - Date.now() 
                : 7 * 24 * 60 * 60 * 1000;

            const sessionCookieOptions = getCookieOptions({
                maxAge: sessionMaxAge > 0 ? sessionMaxAge : 0,
            });
            const refreshCookieOptions = getCookieOptions({
                maxAge: refreshMaxAge > 0 ? refreshMaxAge : 0,
            });

            res.cookie(cookieName, ssoResponse.sessionToken, sessionCookieOptions);
            if (ssoResponse.refreshToken) {
                res.cookie(`${cookieName}_refresh`, ssoResponse.refreshToken, refreshCookieOptions);
            }

            if (options.onLoginSuccess) {
                await options.onLoginSuccess(ssoResponse);
            }

            res.json({
                success: true,
                user: ssoResponse.user,
                tenant: ssoResponse.tenant,
                expiresAt: ssoResponse.expiresAt,
            });
        } catch (error: any) {
            console.error("❌ [BigsoAuthSDK] Error exchanging code:", error.message);
            res.status(500).json({
                error: error.message || "Failed to exchange authorization code",
            });
        }
    });

    /**
     * POST /exchange-v2
     * Exchange signed payload (JWS) for session token (SSO v2.3)
     */
    router.post('/exchange-v2', async (req: import('express').Request, res: import('express').Response) => {
        try {
            const { payload } = req.body;
            if (!payload) {
                res.status(400).json({ error: "Signed payload is required" });
                return;
            }

            const verified = await options.ssoClient.verifySignedPayload(payload, options.frontendUrl);
            if (!verified.code) {
                res.status(400).json({ error: "No authorization code found in payload" });
                return;
            }

            const ssoResponse = await options.ssoClient.exchangeCodeForToken(verified.code);

            if (!ssoResponse.success) {
                res.status(401).json({ error: "Invalid authorization code" });
                return;
            }

            const sessionMaxAge = new Date(ssoResponse.expiresAt).getTime() - Date.now();
            const refreshMaxAge = ssoResponse.refreshExpiresAt 
                ? new Date(ssoResponse.refreshExpiresAt).getTime() - Date.now() 
                : 7 * 24 * 60 * 60 * 1000;

            const sessionCookieOptions = getCookieOptions({
                maxAge: sessionMaxAge > 0 ? sessionMaxAge : 0,
            });
            const refreshCookieOptions = getCookieOptions({
                maxAge: refreshMaxAge > 0 ? refreshMaxAge : 0,
            });

            res.cookie(cookieName, ssoResponse.sessionToken, sessionCookieOptions);
            if (ssoResponse.refreshToken) {
                res.cookie(`${cookieName}_refresh`, ssoResponse.refreshToken, refreshCookieOptions);
            }

            if (options.onLoginSuccess) {
                await options.onLoginSuccess(ssoResponse);
            }

            res.json({
                success: true,
                user: ssoResponse.user,
                tenant: ssoResponse.tenant,
                expiresAt: ssoResponse.expiresAt,
            });
        } catch (error: any) {
            console.error("❌ [BigsoAuthSDK] Error exchanging v2 payload:", error.message);
            res.status(401).json({
                error: error.message || "Failed to verify signed payload",
            });
        }
    });

    /**
     * GET /session
     * Get current session info by validating via SSO
     */
    router.get('/session', ssoAuthMiddleware(options), (req: import('express').Request, res: import('express').Response) => {
        res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
        res.set("Pragma", "no-cache");
        res.set("Expires", "0");

        res.json({
            success: true,
            user: req.user,
            tenant: req.tenant,
            expiresAt: req.ssoSession?.expiresAt,
        });
    });

    /**
     * POST /logout
     */
    router.post('/logout', async (req: import('express').Request, res: import('express').Response) => {
        const sessionToken = req.cookies?.[cookieName];

        if (sessionToken) {
            try {
                await options.ssoClient.revokeSession(sessionToken);
            } catch (error: any) {
                console.warn("⚠️ [BigsoAuthSDK] Failed to revoke session in SSO Backend. Clearing local anyway.", error.message);
            }
        }

        const cookieOptions = getCookieOptions({ maxAge: 0 });
        res.clearCookie(cookieName, cookieOptions);
        res.clearCookie(`${cookieName}_refresh`, cookieOptions);

        if (options.onLogout && sessionToken) {
            await options.onLogout(sessionToken);
        }

        res.json({ success: true, message: "Logged out" });
    });

    return router;
}
