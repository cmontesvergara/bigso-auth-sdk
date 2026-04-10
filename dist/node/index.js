import {
  verifyAccessToken,
  verifySignedPayload
} from "../chunk-PB3GVAEJ.js";

// src/node/SsoClient.ts
var BigsoSsoClient = class {
  constructor(options) {
    this.ssoBackendUrl = options.ssoBackendUrl;
    this.appId = options.appId;
    this.ssoJwksUrl = options.ssoJwksUrl;
  }
  async verifySignedPayload(token, expectedAudience) {
    if (!this.ssoJwksUrl) {
      throw new Error("ssoJwksUrl is required for verifySignedPayload");
    }
    return await verifySignedPayload(token, this.ssoJwksUrl, expectedAudience);
  }
  async validateAccessToken(accessToken) {
    if (!this.ssoJwksUrl) {
      throw new Error("ssoJwksUrl is required for validateAccessToken");
    }
    try {
      return await verifyAccessToken(accessToken, this.ssoJwksUrl);
    } catch {
      return null;
    }
  }
  async login(emailOrNuid, password) {
    const isEmail = emailOrNuid.includes("@");
    const payload = isEmail ? { email: emailOrNuid, password } : { nuid: emailOrNuid, password };
    const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "include"
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || "Login failed");
    }
    return await response.json();
  }
  async exchangeCode(code, codeVerifier) {
    const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        appId: this.appId,
        codeVerifier
      }),
      credentials: "include"
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || "Token exchange failed");
    }
    return await response.json();
  }
  async refreshTokens(refreshToken) {
    const headers = { "Content-Type": "application/json" };
    const body = refreshToken ? JSON.stringify({ refreshToken }) : void 0;
    const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/refresh`, {
      method: "POST",
      headers,
      body,
      credentials: "include"
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || "Token refresh failed");
    }
    return await response.json();
  }
  async logout(accessToken, revokeAll = false) {
    const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`
      },
      body: JSON.stringify({ revokeAll }),
      credentials: "include"
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || "Logout failed");
    }
  }
};
export {
  BigsoSsoClient
};
