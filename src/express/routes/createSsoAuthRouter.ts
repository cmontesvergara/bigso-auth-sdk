import { Router } from 'express';
import { ssoAuthMiddleware } from '../middlewares/ssoAuth';
import type { BigsoSsoClient } from '../../node/SsoClient';
import type { V2ExchangeResponse, SsoUser } from '../../types';

export interface CreateSsoAuthRouterOptions {
    ssoClient: BigsoSsoClient;
    frontendUrl: string;
    onLoginSuccess?: (session: V2ExchangeResponse) => void | Promise<void>;
    onLogout?: (accessToken: string) => void | Promise<void>;
}

export function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router {
    const router = Router();

    router.post('/exchange', async (req: import('express').Request, res: import('express').Response) => {
        try {
            const { code, codeVerifier } = req.body;
            if (!code || !codeVerifier) {
                res.status(400).json({ error: 'code and codeVerifier are required' });
                return;
            }

            const ssoResponse = await options.ssoClient.exchangeCode(code, codeVerifier);

            if (options.onLoginSuccess) {
                await options.onLoginSuccess(ssoResponse);
            }

            res.json({
                success: true,
                tokens: ssoResponse.tokens,
                user: ssoResponse.user,
                tenant: ssoResponse.tenant,
            });
        } catch (error: any) {
            console.error('[BigsoAuthSDK] Error exchanging code:', error.message);
            res.status(401).json({ error: error.message || 'Failed to exchange authorization code' });
        }
    });

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
                tenant: ssoResponse.tenant,
            });
        } catch (error: any) {
            console.error('[BigsoAuthSDK] Error exchanging v2 payload:', error.message);
            res.status(401).json({ error: error.message || 'Failed to verify signed payload' });
        }
    });

    router.get('/session', ssoAuthMiddleware({ ssoClient: options.ssoClient }), (req: import('express').Request, res: import('express').Response) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');

        res.json({
            success: true,
            user: req.user,
            tenant: req.tenant,
            tokenPayload: req.tokenPayload,
        });
    });

    router.post('/refresh', async (req: import('express').Request, res: import('express').Response) => {
        try {
            const ssoResponse = await options.ssoClient.refreshTokens();
            res.json({
                success: true,
                tokens: ssoResponse.tokens,
            });
        } catch (error: any) {
            console.error('[BigsoAuthSDK] Error refreshing tokens:', error.message);
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

            res.json({ success: true, message: 'Logged out' });
        } catch (error: any) {
            console.warn('[BigsoAuthSDK] Failed to logout in SSO Backend.', error.message);
            res.json({ success: true, message: 'Logged out (backend revocation failed)' });
        }
    });

    return router;
}