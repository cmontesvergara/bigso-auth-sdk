export interface BigsoAuthOptions {
    clientId: string
    ssoOrigin: string
    jwksUrl: string
    timeout?: number
    debug?: boolean
    redirectUri?: string
    /** Optional tenant hint. Omit it to let the SSO session select an eligible tenant. */
    tenantId?: string
    theme?: 'light' | 'dark'
    /** Expected audience for signed payload verification.
     *  Defaults to window.location.origin if not provided.
     *  Set this explicitly to avoid environment-dependent mismatches. */
    audience?: string
}

export interface SsoInitPayload {
    state: string
    nonce: string
    code_challenge: string
    code_challenge_method: 'S256'
    origin: string
    redirect_uri?: string
    tenantId?: string
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
    id: string
    name: string
    slug: string
    role: string
    permissions: Array<{
        resource: string;
        action: string;
    }>
}

export interface ActiveSessionApplication {
    appId: string
    name: string
    logoUrl: string | null
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
    tenantId: string
    appId: string
    systemRole: string
    scope: string[]
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
        jti: string
        accessToken: string
        refreshToken: string
        expiresIn: number
    }
    user: SsoUser
    currentTenant: SsoTenant
    relatedTenants: SsoTenant[]
    activeApplications: ActiveSessionApplication[]
}

export interface V2RefreshResponse {
    success: boolean
    tokens: {
        accessToken: string
        expiresIn: number
        refreshToken?: string
    }
    currentTenant?: SsoTenant
}

export interface V2AuthorizeResponse {
    success: boolean
    code: string
    expiresIn: number
    redirectUri: string
    state?: string
}

export type LogoutScope = 'application' | 'global'

export interface LogoutRequest {
    scope: LogoutScope
}

export interface LogoutResult {
    success: boolean
    scope: LogoutScope
    continueUrl?: string
    state?: string
}

export interface BrowserLogoutOptions {
    scope: LogoutScope
    endpoint?: string
    identityOrigin?: string
    fetch?: typeof globalThis.fetch
    navigate?: (url: string) => void
    onTransitionStart?: () => void | Promise<void>
    onTransitionError?: (error: Error) => void | Promise<void>
    storage?: Pick<Storage, 'setItem'>
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

export const CONTEXTUAL_LAUNCH_PROTOCOL = 'bigso-context-launch-v1' as const

export type ContextualLaunchErrorCode =
    | 'session_required'
    | 'tenant_not_eligible'
    | 'application_not_enabled'
    | 'application_access_denied'
    | 'invalid_launch_context'
    | 'authorization_expired'
    | 'exchange_failed'

export interface ContextualLaunchApplication {
    appId: string
    name: string
    url: string
    launchUrl?: string | null
    launchProtocol?: typeof CONTEXTUAL_LAUNCH_PROTOCOL | null
}

export interface ContextualLaunchContext {
    tenantHint?: string
    returnPath: string
    correlationId: string
}

export interface ContextualLaunchAdapterOptions extends BigsoAuthOptions {
    defaultReturnPath?: string
    isSessionReusable?: (tenantId: string) => Promise<boolean>
    onAuthenticated: (result: BigsoAuthResult, returnPath: string) => Promise<void> | void
    navigate: (path: string) => void
    /** Identity-portal route used for top-level contextual authorization. */
    authorizationPath?: string
}
