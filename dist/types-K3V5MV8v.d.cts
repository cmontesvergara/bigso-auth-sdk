interface BigsoAuthOptions {
    clientId: string;
    ssoOrigin: string;
    jwksUrl: string;
    timeout?: number;
    debug?: boolean;
    redirectUri?: string;
    tenantHint?: string;
    theme?: 'light' | 'dark';
}
interface SsoUser {
    userId: string;
    email: string;
    firstName: string;
    lastName: string;
}
interface SsoTenant {
    tenantId: string;
    name: string;
    slug: string;
    role: string;
}
interface SsoJwtTenant {
    id: string;
    name: string;
    slug: string;
    role: string;
    apps: string[];
}
interface SsoTokenPayload {
    sub: string;
    jti: string;
    iss: string;
    aud: string;
    exp: number;
    iat: number;
    tenants: SsoJwtTenant[];
    systemRole: string;
    scope?: string[];
    deviceFingerprint?: string;
}
interface V2LoginResponse {
    success: boolean;
    tokens: {
        accessToken: string;
        expiresIn: number;
    };
    user: SsoUser;
}
interface V2ExchangeResponse {
    success: boolean;
    tokens: {
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    };
    user: SsoUser;
    tenant: SsoTenant;
}
interface V2RefreshResponse {
    success: boolean;
    tokens: {
        accessToken: string;
        expiresIn: number;
    };
}
interface BigsoAuthResult {
    code: string;
    state: string;
    nonce: string;
    codeVerifier: string;
    signed_payload: string;
    tenant?: SsoTenant;
    jti?: string;
    iss?: string;
    aud?: string;
    exp?: number;
    iat?: number;
}

export type { BigsoAuthOptions as B, SsoJwtTenant as S, V2ExchangeResponse as V, BigsoAuthResult as a, SsoTokenPayload as b, V2LoginResponse as c, V2RefreshResponse as d };
