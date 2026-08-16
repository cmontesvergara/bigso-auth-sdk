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
    this.apiVersion = options.apiVersion ?? "v2";
  }
  authUrl(action) {
    const basePath = this.apiVersion === "v1" ? "/v1/auth" : "/api/v2/auth";
    return `${this.ssoBackendUrl}${basePath}/${action}`;
  }
  async performFetch(url, options, operation) {
    const endpoint = new URL(url);
    console.log(`[BigsoSsoClient] START ${operation} | Endpoint: ${endpoint.origin}${endpoint.pathname}`);
    try {
      const response = await fetch(url, options);
      console.log(`[BigsoSsoClient] END ${operation} | Status: ${response.status}`);
      const text = await response.text();
      console.log(`[BigsoSsoClient] Response received (${text.length} bytes)`);
      if (!response.ok) {
        let err = {};
        try {
          err = JSON.parse(text);
        } catch {
          err = {};
        }
        const errorCode = typeof err.error === "string" ? err.error : "upstream_request_failed";
        console.error(`[BigsoSsoClient] Request failed in ${operation}`, {
          status: response.status,
          errorCode
        });
        const requestError = new Error(`${operation} failed (status: ${response.status})`);
        requestError.name = "SsoRequestError";
        Object.assign(requestError, { status: response.status, code: errorCode });
        throw requestError;
      }
      if (!text) return null;
      try {
        return JSON.parse(text);
      } catch {
        return text;
      }
    } catch (error) {
      console.error(`[BigsoSsoClient] Fetch failed in ${operation}`, {
        errorType: error?.name ?? "UnknownError",
        status: typeof error?.status === "number" ? error.status : void 0
      });
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
    return await this.performFetch(this.authUrl("login"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "include"
    }, "login");
  }
  async exchangeCode(code, codeVerifier) {
    return await this.performFetch(this.authUrl("exchange"), {
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
  async authorizeTenant(input) {
    return await this.performFetch(this.authUrl("authorize"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${input.accessToken}`
      },
      body: JSON.stringify({
        tenantId: input.tenantId,
        appId: this.appId,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge,
        codeChallengeMethod: "S256",
        state: input.state
      }),
      credentials: "include"
    }, "authorizeTenant");
  }
  async refreshTokens(refreshToken, tenantId) {
    const headers = { "Content-Type": "application/json" };
    const body = JSON.stringify({ refreshToken, appId: this.appId, tenantId });
    return await this.performFetch(this.authUrl("refresh"), {
      method: "POST",
      headers,
      body,
      credentials: "include"
    }, "refreshTokens");
  }
  async logout(accessToken, options = { scope: "application" }) {
    let sessionId;
    try {
      const parts = accessToken.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        sessionId = payload.sid || payload.jti;
      }
    } catch {
    }
    const scope = typeof options === "boolean" ? options ? "global" : "application" : options.scope;
    if (scope !== "application" && scope !== "global") {
      throw new Error("Unsupported logout scope");
    }
    await this.performFetch(this.authUrl("logout"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`
      },
      body: JSON.stringify({ scope, isGlobal: scope === "global", sessionId }),
      credentials: "include"
    }, "logout");
  }
  async session(sessionId, appId) {
    return await this.performFetch(this.authUrl("session"), {
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
      appId: this.appId,
      apiVersion: this.apiVersion
    };
  }
};
export {
  BigsoSsoClient
};
