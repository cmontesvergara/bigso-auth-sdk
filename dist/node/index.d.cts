import { i as SsoTokenPayload, j as V2LoginResponse, V as V2ExchangeResponse, k as V2RefreshResponse } from '../types-CksaxGxL.cjs';
export { g as LogoutRequest, L as LogoutResult, h as LogoutScope } from '../types-CksaxGxL.cjs';

interface SsoClientOptions {
    ssoBackendUrl: string;
    ssoJwksUrl?: string;
    appId: string;
    /**
     * API version path used for auth endpoints.
     * - 'v2' (default): `${ssoBackendUrl}/api/v2/auth/...`
     * - 'v1': `${ssoBackendUrl}/v1/auth/...` (legacy gateway path alias)
     */
    apiVersion?: 'v1' | 'v2';
}
declare class BigsoSsoClient {
    private ssoBackendUrl;
    private appId;
    private ssoJwksUrl?;
    private apiVersion;
    constructor(options: SsoClientOptions);
    private authUrl;
    private performFetch;
    verifySignedPayload(token: string, expectedAudience: string): Promise<any>;
    validateAccessToken(accessToken: string): Promise<SsoTokenPayload | null>;
    login(emailOrNuid: string, password: string): Promise<V2LoginResponse>;
    exchangeCode(code: string, codeVerifier: string): Promise<V2ExchangeResponse>;
    refreshTokens(refreshToken: string, tenantId: string): Promise<V2RefreshResponse>;
    /** @deprecated Pass `{ scope: 'application' | 'global' }` instead of a boolean. */
    logout(accessToken: string, revokeAll?: boolean): Promise<void>;
    logout(accessToken: string, options?: {
        scope: 'application' | 'global';
    }): Promise<void>;
    session(sessionId: string, appId: string): Promise<any>;
    getClientOptions(): SsoClientOptions;
}

export { BigsoSsoClient, type SsoClientOptions };
