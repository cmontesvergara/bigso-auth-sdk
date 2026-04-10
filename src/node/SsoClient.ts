import { verifySignedPayload, verifyAccessToken } from '../utils/jws';
import type { SsoUser, SsoTenant, SsoTokenPayload, V2ExchangeResponse, V2RefreshResponse, V2LoginResponse } from '../types';

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

    async verifySignedPayload(token: string, expectedAudience: string): Promise<any> {
        if (!this.ssoJwksUrl) {
            throw new Error('ssoJwksUrl is required for verifySignedPayload');
        }
        return await verifySignedPayload(token, this.ssoJwksUrl, expectedAudience);
    }

    async validateAccessToken(accessToken: string): Promise<SsoTokenPayload | null> {
        if (!this.ssoJwksUrl) {
            throw new Error('ssoJwksUrl is required for validateAccessToken');
        }
        try {
            return await verifyAccessToken(accessToken, this.ssoJwksUrl);
        } catch {
            return null;
        }
    }

    async login(emailOrNuid: string, password: string): Promise<V2LoginResponse> {
        const isEmail = emailOrNuid.includes('@');
        const payload = isEmail
            ? { email: emailOrNuid, password }
            : { nuid: emailOrNuid, password };

        const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            credentials: 'include',
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.message || 'Login failed');
        }

        return await response.json() as V2LoginResponse;
    }

    async exchangeCode(code: string, codeVerifier: string): Promise<V2ExchangeResponse> {
        const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/exchange`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                code,
                appId: this.appId,
                codeVerifier,
            }),
            credentials: 'include',
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.message || 'Token exchange failed');
        }

        return await response.json() as V2ExchangeResponse;
    }

    async refreshTokens(refreshToken?: string): Promise<V2RefreshResponse> {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        
        // If refreshToken is provided, include it in the body
        // Otherwise, rely on cookies (credentials: 'include')
        const body = refreshToken ? JSON.stringify({ refreshToken }) : undefined;
        
        const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/refresh`, {
            method: 'POST',
            headers,
            body,
            credentials: 'include',
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.message || 'Token refresh failed');
        }

        return await response.json() as V2RefreshResponse;
    }

    async logout(accessToken: string, revokeAll: boolean = false): Promise<void> {
        const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/logout`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`,
            },
            body: JSON.stringify({ revokeAll }),
            credentials: 'include',
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.message || 'Logout failed');
        }
    }
}