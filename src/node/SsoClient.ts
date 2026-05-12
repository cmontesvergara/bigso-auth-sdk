import type { SsoTokenPayload, V2ExchangeResponse, V2LoginResponse, V2RefreshResponse } from '../types';
import { verifyAccessToken, verifySignedPayload } from '../utils/jws';

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

    private async performFetch(url: string, options: RequestInit, operation: string): Promise<any> {
        console.log(`[BigsoSsoClient] 🚀 START ${operation} | URL: ${url}`);
        console.log(`[BigsoSsoClient] 📦 Request Body:`, options.body);
        
        try {
            const response = await fetch(url, options);
            console.log(`[BigsoSsoClient] 📥 END ${operation} | Status: ${response.status} ${response.statusText}`);
            
            const responseHeaders: Record<string, string> = {};
            response.headers.forEach((value, key) => { responseHeaders[key] = value; });
            console.log(`[BigsoSsoClient] 📑 Response Headers:`, responseHeaders);

            const text = await response.text();
            console.log(`[BigsoSsoClient] 📄 Response Body (${text.length} bytes):`, text ? text.substring(0, 1500) : '<empty>');

            if (!response.ok) {
                let err: any = {};
                try {
                    err = JSON.parse(text);
                } catch {
                    err = { message: `Raw text: ${text.substring(0, 250)}` };
                }
                const errorMsg = err.message || `${operation} failed (status: ${response.status})`;
                console.error(`[BigsoSsoClient] ❌ Error in ${operation}:`, errorMsg, ' | Details:', err);
                throw new Error(errorMsg);
            }

            if (!text) return null;
            try {
                return JSON.parse(text);
            } catch {
                return text;
            }
        } catch (error: any) {
            console.error(`[BigsoSsoClient] 💥 Fatal Fetch Error in ${operation}:`, error.message);
            throw error;
        }
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

        return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            credentials: 'include',
        }, 'login') as V2LoginResponse;
    }

    async exchangeCode(code: string, codeVerifier: string): Promise<V2ExchangeResponse> {
        return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/exchange`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                code,
                appId: this.appId,
                codeVerifier,
            }),
            credentials: 'include',
        }, 'exchangeCode') as V2ExchangeResponse;
    }

    async refreshTokens(refreshToken: string, tenantId: string): Promise<V2RefreshResponse> {
        console.log('TENANT EN refreshTokens:', tenantId);
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };

        const body = JSON.stringify({ refreshToken, appId: this.appId, tenantId });
        console.log('🔄 Refreshing tokens with payload:', { refreshToken, appId: this.appId, tenantId: tenantId });
        
        return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/refresh`, {
            method: 'POST',
            headers,
            body,
            credentials: 'include',
        }, 'refreshTokens') as V2RefreshResponse;
    }

    async logout(accessToken: string, revokeAll: boolean = false): Promise<void> {
        await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/logout`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`,
            },
            body: JSON.stringify({ revokeAll }),
            credentials: 'include',
        }, 'logout');
    }
    async session(sessionId: string, appId: string): Promise<any> {
        return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/session`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ sessionId: sessionId, appId: appId }),
            credentials: 'include',
        }, 'session');
    }

    getClientOptions(): SsoClientOptions {
        return {
            ssoBackendUrl: this.ssoBackendUrl,
            ssoJwksUrl: this.ssoJwksUrl,
            appId: this.appId,
        }
    }
}