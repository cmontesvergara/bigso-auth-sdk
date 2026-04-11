import type { NextFunction, Request, Response } from 'express';
import type { BigsoSsoClient } from '../../node/SsoClient';
import type { SsoJwtTenant, SsoTokenPayload } from '../../types';

export interface SsoAuthMiddlewareOptions {
    ssoClient: BigsoSsoClient;
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
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Missing access token' });
                return;
            }

            const accessToken = authHeader.substring(7);

            const payload = await options.ssoClient.validateAccessToken(accessToken);

            if (!payload) {
                res.status(401).json({ error: 'Invalid or expired access token' });
                return;
            }

             const selectedTenantId = payload.tenantId;
            const tenantInfo =  payload.tenants.find(t => t.id === selectedTenantId) 
            req.user = {
                userId: payload.sub,
                email: '',
                firstName: '',
                lastName: '',
            };
            req.tenant = tenantInfo;
            req.tokenPayload = payload;

            next();
        } catch (error) {
            console.error('[BigsoAuthSDK] Authentication Middleware Error:', error instanceof Error ? error.message : error);
            res.status(401).json({ error: 'Authentication failed' });
        }
    };
}