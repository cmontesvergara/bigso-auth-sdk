interface BigsoAuthOptions {
    clientId: string;
    ssoOrigin: string;
    jwksUrl: string;
    timeout?: number;
    debug?: boolean;
    redirectUri?: string;
    /** Optional tenant hint. Omit it to let the SSO session select an eligible tenant. */
    tenantId?: string;
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
    currentTenant?: SsoTenant;
}
type LogoutScope = 'application' | 'global';
interface LogoutRequest {
    scope: LogoutScope;
}
interface LogoutResult {
    success: boolean;
    scope: LogoutScope;
    continueUrl?: string;
    state?: string;
}
interface BrowserLogoutOptions {
    scope: LogoutScope;
    endpoint?: string;
    identityOrigin?: string;
    fetch?: typeof globalThis.fetch;
    navigate?: (url: string) => void;
    onTransitionStart?: () => void | Promise<void>;
    onTransitionError?: (error: Error) => void | Promise<void>;
    storage?: Pick<Storage, 'setItem'>;
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
declare const CONTEXTUAL_LAUNCH_PROTOCOL: "bigso-context-launch-v1";
type ContextualLaunchErrorCode = 'session_required' | 'tenant_not_eligible' | 'application_not_enabled' | 'application_access_denied' | 'invalid_launch_context' | 'authorization_expired' | 'exchange_failed';
interface ContextualLaunchApplication {
    appId: string;
    name: string;
    url: string;
    launchUrl?: string | null;
    launchProtocol?: typeof CONTEXTUAL_LAUNCH_PROTOCOL | null;
}
interface ContextualLaunchContext {
    tenantHint?: string;
    returnPath: string;
    correlationId: string;
}
interface ContextualLaunchAdapterOptions extends BigsoAuthOptions {
    defaultReturnPath?: string;
    isSessionReusable?: (tenantId: string) => Promise<boolean>;
    onAuthenticated: (result: BigsoAuthResult, returnPath: string) => Promise<void> | void;
    navigate: (path: string) => void;
    /** Identity-portal route used for top-level contextual authorization. */
    authorizationPath?: string;
}

export { type BigsoAuthOptions as B, type ContextualLaunchAdapterOptions as C, type LogoutResult as L, type SsoJwtTenant as S, type V2ExchangeResponse as V, type BigsoAuthResult as a, type ContextualLaunchApplication as b, type ContextualLaunchContext as c, type BrowserLogoutOptions as d, CONTEXTUAL_LAUNCH_PROTOCOL as e, type ContextualLaunchErrorCode as f, type LogoutRequest as g, type LogoutScope as h, type SsoTokenPayload as i, type V2LoginResponse as j, type V2RefreshResponse as k };
