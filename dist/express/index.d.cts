import { Request, Response, NextFunction, Router } from 'express';
import { BigsoSsoClient } from '../node/index.cjs';
import { S as SsoJwtTenant, i as SsoTokenPayload, V as V2ExchangeResponse, j as SsoUser, k as SsoTenant, A as ActiveSessionApplication } from '../types-DPeoi2iF.cjs';

interface SsoAuthMiddlewareOptions {
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
declare function createSsoAuthRouter(options: CreateSsoAuthRouterOptions): Router;

interface PublicAuthResponse {
    success: boolean;
    expiresIn?: number;
    user?: SsoUser;
    currentTenant?: SsoTenant;
    relatedTenants?: SsoTenant[];
    activeApplications?: ActiveSessionApplication[];
    csrfToken?: string;
}
/**
 * Builds the only authentication/session shape that may cross into browser JavaScript.
 * Never spread upstream Identity responses here: new internal fields must remain private by default.
 */
declare function projectPublicAuthResponse(value: unknown): PublicAuthResponse;

interface SsoSyncRouterOptions {
    resources: any[];
    appId: string;
    ssoBackendUrl: string;
    isProduction?: boolean;
}
declare function createSsoSyncRouter(options: SsoSyncRouterOptions): Router;

interface ContextualLaunchRouterOptions {
    ssoClient: BigsoSsoClient;
    cookieConfig: Pick<CookieConfig, 'sessionName'>;
}
declare function createContextualLaunchRouter(options: ContextualLaunchRouterOptions): Router;

export { type ContextualLaunchRouterOptions, type CookieConfig, type CreateSsoAuthRouterOptions, type PublicAuthResponse, type SsoAuthMiddlewareOptions, type SsoSyncGuardOptions, type SsoSyncRouterOptions, createContextualLaunchRouter, createSsoAuthRouter, createSsoSyncRouter, projectPublicAuthResponse, ssoAuthMiddleware, ssoSyncGuardMiddleware };
