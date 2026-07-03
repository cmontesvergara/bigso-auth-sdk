"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/node/index.ts
var node_exports = {};
__export(node_exports, {
  BigsoSsoClient: () => BigsoSsoClient
});
module.exports = __toCommonJS(node_exports);

// src/utils/jws.ts
var import_jose = require("jose");
async function verifySignedPayload(token, jwksUrl, expectedAudience) {
  const JWKS = (0, import_jose.createRemoteJWKSet)(new URL(jwksUrl));
  const { payload } = await (0, import_jose.jwtVerify)(token, JWKS, {
    audience: expectedAudience
  });
  return payload;
}
async function verifyAccessToken(accessToken, jwksUrl) {
  const JWKS = (0, import_jose.createRemoteJWKSet)(new URL(jwksUrl));
  const { payload } = await (0, import_jose.jwtVerify)(accessToken, JWKS);
  if (!payload.sub || !payload.jti) {
    throw new Error("Invalid token structure: missing sub or jti");
  }
  return {
    sub: payload.sub,
    jti: payload.jti,
    iss: payload.iss,
    aud: payload.aud || "",
    exp: payload.exp,
    iat: payload.iat,
    tenants: payload.tenants || [],
    tenantId: payload["https://bigso.co/tenant_id"] || payload.tenantId || "",
    systemRole: payload["https://bigso.co/role"] || payload.systemRole || "user",
    scope: payload.scope,
    deviceFingerprint: payload.deviceFingerprint
  };
}

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
  async refreshTokens(refreshToken, tenantId) {
    console.log("TENANT EN refreshTokens:", tenantId);
    const headers = { "Content-Type": "application/json" };
    const body = JSON.stringify({ refreshToken, appId: this.appId, tenantId });
    console.log("\u{1F504} Refreshing tokens with payload:", { refreshToken, appId: this.appId, tenantId });
    return await this.performFetch(this.authUrl("refresh"), {
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
    await this.performFetch(this.authUrl("logout"), {
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  BigsoSsoClient
});
