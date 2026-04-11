export interface BigsoAuthOptions {
    clientId: string
    ssoOrigin: string
    jwksUrl: string
    timeout?: number
    debug?: boolean
    redirectUri?: string
    tenantHint?: string
    theme?: 'light' | 'dark'
}

export interface SsoInitPayload {
    state: string
    nonce: string
    code_challenge: string
    code_challenge_method: 'S256'
    origin: string
    redirect_uri?: string
    tenant_hint?: string
    timeout_ms?: number
}

export interface SsoSuccessPayload {
    signed_payload: string
    state: string
}

export interface SsoErrorPayload {
    code: string
    message?: string
    expected_version?: string
}

export type AuthEvents =
    | 'ready'
    | 'success'
    | 'error'
    | 'fallback'
    | 'debug'

export interface SsoUser {
    userId: string
    email: string
    firstName: string
    lastName: string
}

export interface SsoTenant {
    tenantId: string
    name: string
    slug: string
    role: string
}

export interface SsoJwtTenant {
    id: string
    name: string
    slug: string
    role: string
    apps: string[]
}

export interface SsoTokenPayload {
    sub: string
    jti: string
    iss: string
    aud: string
    exp: number
    iat: number
    tenants: SsoJwtTenant[]
    tenantId: string
    systemRole: string
    scope?: string[]
    deviceFingerprint?: string
}

export interface V2LoginResponse {
    success: boolean
    tokens: {
        accessToken: string
        expiresIn: number
    }
    user: SsoUser
}

export interface V2ExchangeResponse {
    success: boolean
    tokens: {
        accessToken: string
        refreshToken: string
        expiresIn: number
    }
    user: SsoUser
    tenant: SsoTenant
}

export interface V2RefreshResponse {
    success: boolean
    tokens: {
        accessToken: string
        expiresIn: number
    }
}

export interface V2AuthorizeResponse {
    success: boolean
    code: string
    expiresIn: number
    redirectUri: string
    state?: string
}

export interface BigsoAuthResult {
    code: string
    state: string
    nonce: string
    codeVerifier: string
    signed_payload: string
    tenant?: SsoTenant
    jti?: string
    iss?: string
    aud?: string
    exp?: number
    iat?: number
}