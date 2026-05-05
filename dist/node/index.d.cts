import { b as SsoTokenPayload, c as V2LoginResponse, V as V2ExchangeResponse, d as V2RefreshResponse } from '../types-QgcejP9D.cjs';

interface SsoClientOptions {
    ssoBackendUrl: string;
    ssoJwksUrl?: string;
    appId: string;
}
declare class BigsoSsoClient {
    private ssoBackendUrl;
    private appId;
    private ssoJwksUrl?;
    constructor(options: SsoClientOptions);
    verifySignedPayload(token: string, expectedAudience: string): Promise<any>;
    validateAccessToken(accessToken: string): Promise<SsoTokenPayload | null>;
    login(emailOrNuid: string, password: string): Promise<V2LoginResponse>;
    exchangeCode(code: string, codeVerifier: string): Promise<V2ExchangeResponse>;
    refreshTokens(refreshToken: string, tenantId: string): Promise<V2RefreshResponse>;
    logout(accessToken: string, revokeAll?: boolean): Promise<void>;
    session(sessionId: string, appId: string): Promise<any>;
    getClientOptions(): SsoClientOptions;
}

export { BigsoSsoClient, type SsoClientOptions };
