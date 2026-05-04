import { Request, Response, NextFunction, Router } from 'express';
import { BigsoSsoClient } from '../node/index.cjs';
import { S as SsoJwtTenant, b as SsoTokenPayload, V as V2ExchangeResponse } from '../types-Y2yH3pEh.cjs';

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
}
interface CreateSsoAuthRouterOptions {
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
declare function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router;

interface SsoSyncRouterOptions {
    resources: any[];
    appId: string;
    ssoBackendUrl: string;
    isProduction?: boolean;
}
declare function createSsoSyncRouter(options: SsoSyncRouterOptions): Router;

export { type CookieConfig, type CreateSsoAuthRouterOptions, type SsoAuthMiddlewareOptions, type SsoSyncGuardOptions, type SsoSyncRouterOptions, createSsoAuthRouter, createSsoSyncRouter, ssoAuthMiddleware, ssoSyncGuardMiddleware };
