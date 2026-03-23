import { verifySignedPayload } from '../utils/jws';
import type { SsoSessionData, SsoExchangeResponse, SsoRefreshData } from '../types';

export interface SsoClientOptions {
    ssoBackendUrl: string;
    ssoJwksUrl?: string;
    appId: string;
}

export class BigsoSsoClient {
    private ssoBackendUrl: string;
    private appId: string;
    private ssoJwksUrl?: string;

    constructor(options: SsoClientOptions) {
        this.ssoBackendUrl = options.ssoBackendUrl;
        this.appId = options.appId;
        this.ssoJwksUrl = options.ssoJwksUrl;
    }

    /**
     * Verify a signed payload (JWS) against the SSO's JWKS
     * @param token - The compact JWS token
     * @param expectedAudience - The expected audience (app origin)
     * @returns The verified payload
     */
    async verifySignedPayload(token: string, expectedAudience: string): Promise<any> {
        if (!this.ssoJwksUrl) {
            throw new Error('ssoJwksUrl is required for verifySignedPayload');
        }
        return await verifySignedPayload(token, this.ssoJwksUrl, expectedAudience);
    }

    /**
     * Validate session token with SSO Backend
     * @param sessionToken - JWT token from cookie
     * @returns Session data or null if invalid
     */
    async validateSessionToken(sessionToken: string): Promise<SsoSessionData | null> {
        try {
            const response = await fetch(`${this.ssoBackendUrl}/api/v1/auth/verify-session`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    sessionToken,
                    appId: this.appId,
                }),
                // Node 18+ allows abort signals to enforce timeout, but we will rely on native fetch timeout if available or no timeout for simplicity.
                // In production, we might want to implement an AbortController wrapper.
            });

            if (!response.ok) {
                return null;
            }

            const data = await response.json() as any;
            if (data.valid) {
                return {
                    user: data.user,
                    tenant: data.tenant,
                    appId: data.appId,
                    expiresAt: data.expiresAt,
                };
            }
            return null;
        } catch (error) {
            console.error("❌ [BigsoSsoClient] Error validating session:", error instanceof Error ? error.message : error);
            return null;
        }
    }

    /**
     * Exchange authorization code for session token from SSO
     * @param code - The auth code
     * @returns The SSO exchange response
     */
    async exchangeCodeForToken(code: string): Promise<SsoExchangeResponse> {
        const response = await fetch(`${this.ssoBackendUrl}/api/v1/auth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                authCode: code,
                appId: this.appId,
            }),
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.message || 'Failed to exchange token');
        }

        return await response.json() as SsoExchangeResponse;
    }

    /**
     * Revoke session in SSO backend
     * @param sessionToken - The active session token
     */
    async revokeSession(sessionToken: string): Promise<void> {
        const response = await fetch(`${this.ssoBackendUrl}/api/v1/session/revoke`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${sessionToken}`,
            },
        });

        if (!response.ok) {
            throw new Error('Failed to revoke session');
        }
    }

    /**
     * Refreshes the application session using a refresh token
     * @param refreshToken - The stored refresh token
     * @returns The new session tokens or null if failed
     */
    async refreshAppSession(refreshToken: string): Promise<SsoRefreshData | null> {
        try {
            const response = await fetch(`${this.ssoBackendUrl}/api/v1/auth/app-refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    refreshToken,
                    appId: this.appId,
                }),
            });

            if (!response.ok) {
                return null;
            }

            const data = await response.json() as any;
            if (data.success) {
                return {
                    sessionToken: data.sessionToken,
                    refreshToken: data.refreshToken,
                    expiresAt: data.expiresAt,
                    refreshExpiresAt: data.refreshExpiresAt,
                };
            }
            return null;
        } catch (error) {
            console.error("❌ [BigsoSsoClient] Error refreshing app session:", error instanceof Error ? error.message : error);
            return null;
        }
    }
}
