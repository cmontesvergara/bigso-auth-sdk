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
    systemRole: payload.systemRole || "user",
    deviceFingerprint: payload.deviceFingerprint
  };
}

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
  async refreshTokens() {
    const response = await fetch(`${this.ssoBackendUrl}/api/v2/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  BigsoSsoClient
});
