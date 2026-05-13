import {
  verifyAccessToken,
  verifySignedPayload
} from "../chunk-BSPSXDAQ.js";

// src/node/SsoClient.ts
var BigsoSsoClient = class {
  constructor(options) {
    this.ssoBackendUrl = options.ssoBackendUrl;
    this.appId = options.appId;
    this.ssoJwksUrl = options.ssoJwksUrl;
  }
  async performFetch(url, options, operation) {
    console.log(`[BigsoSsoClient] \u{1F680} START ${operation} | URL: ${url}`);
    console.log(`[BigsoSsoClient] \u{1F4E6} Request Body:`, options.body);
    try {
      const response = await fetch(url, options);
      console.log(`[BigsoSsoClient] \u{1F4E5} END ${operation} | Status: ${response.status} ${response.statusText}`);
      const responseHeaders = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });
      console.log(`[BigsoSsoClient] \u{1F4D1} Response Headers:`, responseHeaders);
      const text = await response.text();
      console.log(`[BigsoSsoClient] \u{1F4C4} Response Body (${text.length} bytes):`, text ? text.substring(0, 1500) : "<empty>");
      if (!response.ok) {
        let err = {};
        try {
          err = JSON.parse(text);
        } catch {
          err = { message: `Raw text: ${text.substring(0, 250)}` };
        }
        const errorMsg = err.message || `${operation} failed (status: ${response.status})`;
        console.error(`[BigsoSsoClient] \u274C Error in ${operation}:`, errorMsg, " | Details:", err);
        throw new Error(errorMsg);
      }
      if (!text) return null;
      try {
        return JSON.parse(text);
      } catch {
        return text;
      }
    } catch (error) {
      console.error(`[BigsoSsoClient] \u{1F4A5} Fatal Fetch Error in ${operation}:`, error.message);
      throw error;
    }
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
    return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "include"
    }, "login");
  }
  async exchangeCode(code, codeVerifier) {
    return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        appId: this.appId,
        codeVerifier
      }),
      credentials: "include"
    }, "exchangeCode");
  }
  async refreshTokens(refreshToken, tenantId) {
    console.log("TENANT EN refreshTokens:", tenantId);
    const headers = { "Content-Type": "application/json" };
    const body = JSON.stringify({ refreshToken, appId: this.appId, tenantId });
    console.log("\u{1F504} Refreshing tokens with payload:", { refreshToken, appId: this.appId, tenantId });
    return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/refresh`, {
      method: "POST",
      headers,
      body,
      credentials: "include"
    }, "refreshTokens");
  }
  async logout(accessToken, revokeAll = false) {
    let sessionId;
    try {
      const parts = accessToken.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        sessionId = payload.jti;
      }
    } catch {
    }
    await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`
      },
      body: JSON.stringify({ revokeAll, sessionId }),
      credentials: "include"
    }, "logout");
  }
  async session(sessionId, appId) {
    return await this.performFetch(`${this.ssoBackendUrl}/api/v2/auth/session`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ sessionId, appId }),
      credentials: "include"
    }, "session");
  }
  getClientOptions() {
    return {
      ssoBackendUrl: this.ssoBackendUrl,
      ssoJwksUrl: this.ssoJwksUrl,
      appId: this.appId
    };
  }
};
export {
  BigsoSsoClient
};
