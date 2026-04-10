import { Request, Response, NextFunction, Router } from 'express';
import { BigsoSsoClient } from '../node/index.js';
import { S as SsoJwtTenant, b as SsoTokenPayload, V as V2ExchangeResponse } from '../types-K3V5MV8v.js';

interface SsoAuthMiddlewareOptions {
    ssoClient: BigsoSsoClient;
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

interface SsoSyncGuardOptions {
    ssoBackendUrl: string;
    isProduction?: boolean;
}
declare function ssoSyncGuardMiddleware(options: SsoSyncGuardOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;

interface CreateSsoAuthRouterOptions {
    ssoClient: BigsoSsoClient;
    frontendUrl: string;
    onLoginSuccess?: (session: V2ExchangeResponse) => void | Promise<void>;
    onLogout?: (accessToken: string) => void | Promise<void>;
}
declare function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router;

interface SsoSyncRouterOptions {
    resources: any[];
    appId: string;
    ssoBackendUrl: string;
    isProduction?: boolean;
}
declare function createSsoSyncRouter(options: SsoSyncRouterOptions): Router;

export { type CreateSsoAuthRouterOptions, type SsoAuthMiddlewareOptions, type SsoSyncGuardOptions, type SsoSyncRouterOptions, createSsoAuthRouter, createSsoSyncRouter, ssoAuthMiddleware, ssoSyncGuardMiddleware };
