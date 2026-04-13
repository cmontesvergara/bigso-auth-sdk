import { Router } from 'express';
import type { BigsoSsoClient } from '../../node/SsoClient';
import type { V2ExchangeResponse } from '../../types';
import { ssoAuthMiddleware } from '../middlewares/ssoAuth';

export interface CreateSsoAuthRouterOptions {
    ssoClient: BigsoSsoClient;
    frontendUrl: string;
    onLoginSuccess?: (session: V2ExchangeResponse) => void | Promise<void>;
    onLogout?: (accessToken: string) => void | Promise<void>;
}

function validateRequiredEnvs() {
    const requiredEnvs = ['COOKIE_DOMAIN', 'COOKIE_SAMESITE'];
    const missingEnvs = requiredEnvs.filter(env => !process.env[env]);
    if (missingEnvs.length > 0) {
        throw new Error(`Missing required environment variables: ${missingEnvs.join(', ')}`);
    }
}

function extractCookieValueFromMap(cookieMapStr: string | undefined, key: string): string | null {
    if (!cookieMapStr) return null;

    try {
        const cookieMap = JSON.parse(cookieMapStr);
        const entry = cookieMap.find((item: string) => item.startsWith(`${key}:`));
        return entry ? entry.split(':')[1] : null;
    } catch (error) {
        console.warn('[BigsoAuthSDK] Failed to parse cookie name map:', error);
        return null;
    }
}
function extractCookieNameFromMap(cookieMapStr: string | undefined, key: string): string | null {
    if (!cookieMapStr) return null;

    try {
        const cookieMap = JSON.parse(cookieMapStr);
        const entry = cookieMap.find((item: string) => item.startsWith(`${key}:`));
        return entry ? entry.split(':')[0] : null;
    } catch (error) {
        console.warn('[BigsoAuthSDK] Failed to parse cookie name map:', error);
        return null;
    }
}

export function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router {
    validateRequiredEnvs();
    const router = Router();

    router.post('/exchange-v2', async (req: import('express').Request, res: import('express').Response) => {
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

            if (options.onLoginSuccess) {
                await options.onLoginSuccess(ssoResponse);
            }

            res.json({
                success: true,
                tokens: ssoResponse.tokens,
                user: ssoResponse.user,
                currentTenant: ssoResponse.currentTenant,
                relatedTenants: ssoResponse.relatedTenants,
            });
        } catch (error: any) {
            console.error('[BigsoAuthSDK] Error exchanging v2 payload:', error.message);
            res.status(401).json({ error: error.message || 'Failed to verify signed payload' });
        }
    });

    router.post('/session', ssoAuthMiddleware({ ssoClient: options.ssoClient }), async (req: import('express').Request, res: import('express').Response) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');

        const sessionId = extractCookieValueFromMap(req.cookies?.['bs_cookie_name_map'], 'sessionId');
        const ssoSession = await options.ssoClient.session(req.headers.authorization?.substring(7) as string, sessionId as string, req.tokenPayload?.appId as string);
        res.json({
            success: true,
            ...ssoSession,
            tokenPayload: req.tokenPayload,
        });
    });

    router.post('/refresh', async (req: import('express').Request, res: import('express').Response) => {
        const refreshTokenCookieName = extractCookieNameFromMap(req.cookies?.['bs_cookie_name_map'], 'refreshToken') as string;
        try {
            const refreshToken = extractCookieValueFromMap(req.cookies?.['bs_cookie_name_map'], 'refreshToken') as string;

            const ssoResponse = await options.ssoClient.refreshTokens(refreshToken);

            if (ssoResponse.tokens?.refreshToken) {
                res.cookie(refreshTokenCookieName, ssoResponse.tokens.refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: process.env.COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
                    path: '/api/auth/refresh',
                    maxAge: 7 * 24 * 60 * 60 * 1000,
                    domain: process.env.COOKIE_DOMAIN
                })

            } else {
                console.warn('[BigsoAuthSDK] No refresh token received in refresh response, not setting cookie');
            }
            res.json({
                success: true,
                tokens: ssoResponse.tokens,
            });
        } catch (error: any) {
            console.error('[BigsoAuthSDK] Error refreshing tokens:', error.message);

            if (error.message?.includes('revoked') || error.message?.includes('expired') || error.message?.includes('Invalid')) {

                res.clearCookie(refreshTokenCookieName, {
                    path: '/api/auth/refresh',
                    domain: process.env.COOKIE_DOMAIN
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

            res.clearCookie(process.env.REFRESH_COOKIE_NAME as string, {
                path: '/api/auth/refresh',
                domain: process.env.COOKIE_DOMAIN
            });

            res.json({ success: true, message: 'Logged out' });
        } catch (error: any) {
            console.warn('[BigsoAuthSDK] Failed to logout in SSO Backend.', error.message);

            res.clearCookie(process.env.REFRESH_COOKIE_NAME as string, {
                path: '/api/auth/refresh',
                domain: process.env.COOKIE_DOMAIN
            });

            res.json({ success: true, message: 'Logged out (backend revocation failed)' });
        }
    });

    return router;
}


