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

// src/express/index.ts
var express_exports = {};
__export(express_exports, {
  createSsoAuthRouter: () => createSsoAuthRouter,
  createSsoSyncRouter: () => createSsoSyncRouter,
  ssoAuthMiddleware: () => ssoAuthMiddleware,
  ssoSyncGuardMiddleware: () => ssoSyncGuardMiddleware
});
module.exports = __toCommonJS(express_exports);

// src/express/middlewares/ssoAuth.ts
function ssoAuthMiddleware(options) {
  return async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({ error: "Missing access token" });
        return;
      }
      const accessToken = authHeader.substring(7);
      const payload = await options.ssoClient.validateAccessToken(accessToken);
      if (!payload) {
        res.status(401).json({ error: "Invalid or expired access token" });
        return;
      }
      req.tokenPayload = payload;
      next();
    } catch (error) {
      console.error("[BigsoAuthSDK] Authentication Middleware Error:", error instanceof Error ? error.message : error);
      res.status(401).json({ error: "Authentication failed" });
    }
  };
}

// src/express/middlewares/ssoSyncGuard.ts
var import_dns = require("dns");
function ssoSyncGuardMiddleware(options) {
  const isProduction = options.isProduction ?? process.env.NODE_ENV === "production";
  return async (req, res, next) => {
    try {
      const isSecure = req.secure || req.headers["x-forwarded-proto"] === "https";
      if (!isSecure && isProduction) {
        console.warn("\u26A0\uFE0F  [BigsoAuthSDK] Blocked non-HTTPS sync request");
        res.status(403).json({ error: "HTTPS required" });
        return;
      }
      const clientIp = req.ip || req.socket.remoteAddress || "";
      const isLoopback = clientIp === "::1" || clientIp === "127.0.0.1" || clientIp === "::ffff:127.0.0.1";
      if (!isProduction && isLoopback) {
        return next();
      }
      const ssoUrl = new URL(options.ssoBackendUrl);
      const ssoHostname = ssoUrl.hostname;
      const ssoIps = await import_dns.promises.resolve4(ssoHostname).catch(() => []);
      const cleanClientIp = clientIp.replace(/^.*:/, "");
      const isPrivateIp = cleanClientIp.startsWith("10.") || cleanClientIp.startsWith("192.168.") || cleanClientIp.startsWith("172.") && parseInt(cleanClientIp.split(".")[1], 10) >= 16 && parseInt(cleanClientIp.split(".")[1], 10) <= 31;
      if (!ssoIps.includes(cleanClientIp) && !isPrivateIp) {
        console.warn(`\u26D4\uFE0F [BigsoAuthSDK] Blocked sync request from unauthorized IP: ${clientIp}`);
        res.status(403).json({ error: "Unauthorized origin" });
        return;
      }
      next();
    } catch (error) {
      console.error("\u274C [BigsoAuthSDK] Sync Guard Validation Error:", error instanceof Error ? error.message : error);
      res.status(500).json({ error: "Security validation failed" });
    }
  };
}

// src/express/routes/createSsoAuthRouter.ts
var import_express = require("express");
function validateRequiredEnvs(cookieConfig) {
  if (cookieConfig) {
    return;
  }
  const requiredEnvs = ["COOKIE_DOMAIN", "COOKIE_SAMESITE"];
  const missingEnvs = requiredEnvs.filter((env) => !process.env[env]);
  if (missingEnvs.length > 0) {
    throw new Error(`Missing required environment variables: ${missingEnvs.join(", ")}`);
  }
}
function extractCookieValueFromMap(cookieMapStr, key) {
  if (!cookieMapStr) return null;
  try {
    const cookieMap = JSON.parse(cookieMapStr);
    const entry = cookieMap.find((item) => item.startsWith(`${key}:`));
    return entry ? entry.split(":")[1] : null;
  } catch (error) {
    console.warn("[BigsoAuthSDK] Failed to parse cookie name map:", error);
    return null;
  }
}
function extractCookieNameFromMap(cookieMapStr, key) {
  if (!cookieMapStr) return null;
  try {
    const cookieMap = JSON.parse(cookieMapStr);
    const entry = cookieMap.find((item) => item.startsWith(`${key}:`));
    return entry ? entry.split(":")[0] : null;
  } catch (error) {
    console.warn("[BigsoAuthSDK] Failed to parse cookie name map:", error);
    return null;
  }
}
function createSsoAuthRouter(options) {
  validateRequiredEnvs();
  const router = (0, import_express.Router)();
  router.post("/exchange-v2", async (req, res) => {
    try {
      const { payload, codeVerifier: codeVerifierFromBody } = req.body;
      if (!payload) {
        res.status(400).json({ error: "Signed payload is required" });
        return;
      }
      const verified = await options.ssoClient.verifySignedPayload(payload, options.frontendUrl);
      if (!verified.code) {
        res.status(400).json({ error: "No authorization code found in payload" });
        return;
      }
      const verifier = codeVerifierFromBody || verified.code_verifier;
      if (!verifier) {
        res.status(400).json({ error: "codeVerifier is required for PKCE exchange" });
        return;
      }
      const ssoResponse = await options.ssoClient.exchangeCode(verified.code, verifier);
      if (options.cookieConfig && ssoResponse.tokens?.refreshToken) {
        const cookieConfig = options.cookieConfig;
        const maxAge = cookieConfig.maxAge || 7 * 24 * 60 * 60 * 1e3;
        res.cookie(cookieConfig.name, ssoResponse.tokens.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieConfig.sameSite,
          path: cookieConfig.path,
          maxAge,
          domain: cookieConfig.domain
        });
      }
      if (options.onLoginSuccess) {
        await options.onLoginSuccess(ssoResponse);
      }
      res.json({
        success: true,
        tokens: ssoResponse.tokens,
        user: ssoResponse.user,
        currentTenant: ssoResponse.currentTenant,
        relatedTenants: ssoResponse.relatedTenants
      });
    } catch (error) {
      console.error("[BigsoAuthSDK] Error exchanging v2 payload:", error.message);
      res.status(401).json({ error: error.message || "Failed to verify signed payload" });
    }
  });
  router.post("/session", ssoAuthMiddleware({ ssoClient: options.ssoClient }), async (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    const sessionId = extractCookieValueFromMap(req.cookies?.["bs_cookie_name_map"], "sessionId");
    const ssoSession = await options.ssoClient.session(req.headers.authorization?.substring(7), sessionId, req.tokenPayload?.appId);
    res.json({
      success: true,
      ...ssoSession,
      tokenPayload: req.tokenPayload
    });
  });
  router.post("/refresh", async (req, res) => {
    const cookieConfig = options.cookieConfig;
    const refreshTokenCookieName = cookieConfig ? cookieConfig.name : extractCookieNameFromMap(req.cookies?.["bs_cookie_name_map"], "refreshToken");
    const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
    const cookiePath = cookieConfig ? cookieConfig.path : "/api/auth/refresh";
    const cookieSameSite = cookieConfig ? cookieConfig.sameSite : process.env.COOKIE_SAMESITE;
    try {
      const refreshToken = cookieConfig ? req.cookies?.[cookieConfig.name] : extractCookieValueFromMap(req.cookies?.["bs_cookie_name_map"], "refreshToken");
      if (!refreshToken) {
        res.status(401).json({ error: "No refresh token available" });
        return;
      }
      const ssoResponse = await options.ssoClient.refreshTokens(refreshToken);
      if (ssoResponse.tokens?.refreshToken) {
        const maxAge = cookieConfig?.maxAge || 7 * 24 * 60 * 60 * 1e3;
        res.cookie(refreshTokenCookieName, ssoResponse.tokens.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieSameSite,
          path: cookiePath,
          maxAge,
          domain: cookieDomain
        });
      } else {
        console.warn("[BigsoAuthSDK] No refresh token received in refresh response, not setting cookie");
      }
      res.json({
        success: true,
        tokens: ssoResponse.tokens
      });
    } catch (error) {
      console.error("[BigsoAuthSDK] Error refreshing tokens:", error.message);
      if (error.message?.includes("revoked") || error.message?.includes("expired") || error.message?.includes("Invalid")) {
        res.clearCookie(refreshTokenCookieName, {
          path: cookiePath,
          domain: cookieDomain
        });
      }
      res.status(401).json({ error: error.message || "Failed to refresh tokens" });
    }
  });
  router.post("/logout", ssoAuthMiddleware({ ssoClient: options.ssoClient }), async (req, res) => {
    try {
      const accessToken = req.headers.authorization?.substring(7) || "";
      const { revokeAll = false } = req.body || {};
      await options.ssoClient.logout(accessToken, revokeAll);
      if (options.onLogout) {
        await options.onLogout(accessToken);
      }
      const cookieConfig = options.cookieConfig;
      const cookieName = cookieConfig ? cookieConfig.name : process.env.REFRESH_COOKIE_NAME;
      const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
      const cookiePath = cookieConfig ? cookieConfig.path : "/api/auth/refresh";
      res.clearCookie(cookieName, {
        path: cookiePath,
        domain: cookieDomain
      });
      res.json({ success: true, message: "Logged out" });
    } catch (error) {
      console.warn("[BigsoAuthSDK] Failed to logout in SSO Backend.", error.message);
      const cookieConfig = options.cookieConfig;
      const cookieName = cookieConfig ? cookieConfig.name : process.env.REFRESH_COOKIE_NAME;
      const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
      const cookiePath = cookieConfig ? cookieConfig.path : "/api/auth/refresh";
      res.clearCookie(cookieName, {
        path: cookiePath,
        domain: cookieDomain
      });
      res.json({ success: true, message: "Logged out (backend revocation failed)" });
    }
  });
  return router;
}

// src/express/routes/createSsoSyncRouter.ts
var import_express2 = require("express");
function createSsoSyncRouter(options) {
  const router = (0, import_express2.Router)();
  router.get("/resources", ssoSyncGuardMiddleware({
    ssoBackendUrl: options.ssoBackendUrl,
    isProduction: options.isProduction
  }), (req, res) => {
    try {
      res.json({
        success: true,
        resources: options.resources,
        meta: {
          appId: options.appId,
          count: options.resources.length,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        }
      });
    } catch (error) {
      console.error("\u274C [BigsoAuthSDK] Error in sync endpoint:", error.message);
      res.status(500).json({ error: error.message });
    }
  });
  return router;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createSsoAuthRouter,
  createSsoSyncRouter,
  ssoAuthMiddleware,
  ssoSyncGuardMiddleware
});
