interface BigsoAuthOptions {
    clientId: string;
    ssoOrigin: string;
    jwksUrl: string;
    timeout?: number;
    debug?: boolean;
    redirectUri?: string;
    tenantHint?: string;
    theme?: 'light' | 'dark';
    /** Expected audience for signed payload verification.
     *  Defaults to window.location.origin if not provided.
     *  Set this explicitly to avoid environment-dependent mismatches. */
    audience?: string;
}
interface SsoUser {
    userId: string;
    email: string;
    firstName: string;
    lastName: string;
}
interface SsoTenant {
    id: string;
    name: string;
    slug: string;
    role: string;
    permissions: Array<{
        resource: string;
        action: string;
    }>;
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
    tenantId: string;
    appId: string;
    systemRole: string;
    scope: string[];
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
        jti: string;
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    };
    user: SsoUser;
    currentTenant: SsoTenant;
    relatedTenants: SsoTenant[];
}
interface V2RefreshResponse {
    success: boolean;
    tokens: {
        accessToken: string;
        expiresIn: number;
        refreshToken?: string;
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
