import type { NextFunction, Request, Response } from 'express';
import type { BigsoSsoClient } from '../../node/SsoClient';
import type { SsoJwtTenant, SsoTokenPayload } from '../../types';
import { SdkLogger } from '../../utils/logger';

const logger = new SdkLogger('AuthSDK');

export interface SsoAuthMiddlewareOptions {
    ssoClient: BigsoSsoClient;
    /**
     * Cookie de sesión para fallback cuando no hay Authorization header.
     * Permite que window.open() y navegaciones directas funcionen sin
     * que el frontend inyecte manualmente el Bearer token.
     *
     * Si se proporciona, el middleware lee la cookie `sessionName`,
     * resuelve la sesión via SSO y extrae el accessToken.
     */
    cookieConfig?: {
        sessionName: string;
    };
}

declare global {
    namespace Express {
        interface Request {
            user?: { userId: string; email: string; firstName: string; lastName: string };
            tenant?: SsoJwtTenant;
            tokenPayload?: SsoTokenPayload;
        }
    }
}

export function ssoAuthMiddleware(options: SsoAuthMiddlewareOptions) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            let accessToken: string | undefined;

            // Fast path: Authorization: Bearer header (XHR requests from frontend)
            const authHeader = req.headers.authorization;
            if (authHeader?.startsWith('Bearer ')) {
                accessToken = authHeader.substring(7);
            }

            // Fallback: cookie de sesión (window.open, navegación directa)
            // El browser envía cookies pero no headers custom.
            // La cookie contiene el jti (session ID), no el access token.
            if (!accessToken && options.cookieConfig?.sessionName && req.cookies) {
                const sessionId = req.cookies[options.cookieConfig.sessionName] as string | undefined;
                if (sessionId) {
                    logger.info('Resolving authentication from application session');
                    const ssoClientOptions = options.ssoClient.getClientOptions();
                    const session = await options.ssoClient.session(sessionId, ssoClientOptions.appId);
                    accessToken = session?.tokens?.accessToken;
                }
            }

            if (!accessToken) {
                res.status(401).json({ error: 'Missing access token' });
                return;
            }

            const payload = await options.ssoClient.validateAccessToken(accessToken);
            if (!payload) {
                res.status(401).json({ error: 'Invalid or expired access token' });
                return;
            }

            req.tokenPayload = payload;

            next();
        } catch (error) {
            logger.error('Authentication middleware failed', {
                errorType: error instanceof Error ? error.name : 'UnknownError',
            });
            res.status(401).json({ error: 'Authentication failed' });
        }
    };
}
