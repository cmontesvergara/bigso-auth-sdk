import { b as SsoTokenPayload, c as V2LoginResponse, V as V2ExchangeResponse, d as V2RefreshResponse } from '../types-K3V5MV8v.js';

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
    refreshTokens(): Promise<V2RefreshResponse>;
    logout(accessToken: string, revokeAll?: boolean): Promise<void>;
}

export { BigsoSsoClient, type SsoClientOptions };
