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
      console.log("[BigsoAuthSDK] Access Token Payload:", payload);
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
import { promises as dns } from "dns";
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
      const ssoIps = await dns.resolve4(ssoHostname).catch(() => []);
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
import { Router } from "express";
function serializePermissions(permissions) {
  return permissions.map((p) => `${p.resource}:${p.action}`).join(",");
}
function createSsoAuthRouter(options) {
  const router = Router();
  router.post("/exchange", async (req, res) => {
    console.log("[BigsoAuthSDK] Received /exchange-v2 request with body:", req.body);
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
      if (options.cookieConfig) {
        console.log("[BigsoAuthSDK] Setting refresh token cookie with custom config:", options.cookieConfig);
        const cookieConfig = options.cookieConfig;
        res.cookie(cookieConfig.sessionName, ssoResponse.tokens.jti, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieConfig.sameSite,
          path: cookieConfig.sessionPath,
          maxAge: cookieConfig.maxAge,
          domain: cookieConfig.domain
        });
        res.cookie(cookieConfig.refreshName, ssoResponse.tokens.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieConfig.sameSite,
          path: cookieConfig.refreshPath,
          maxAge: cookieConfig.maxAge,
          domain: cookieConfig.domain
        });
        res.cookie(cookieConfig.permissionName, serializePermissions(ssoResponse.currentTenant.permissions), {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieConfig.sameSite,
          path: cookieConfig.permissionPath,
          maxAge: cookieConfig.maxAge,
          domain: cookieConfig.domain
        });
      }
      if (options.onLoginSuccess) {
        await options.onLoginSuccess(ssoResponse);
      }
      delete ssoResponse.tokens.refreshToken;
      res.json(ssoResponse);
    } catch (error) {
      console.error("[BigsoAuthSDK] Error exchanging v2 payload:", error.message);
      res.status(401).json({ error: error.message || "Failed to verify signed payload" });
    }
  });
  router.get("/session", async (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    if (options.cookieConfig) {
      console.log("[BigsoAuthSDK] session config", options.cookieConfig);
      const cookieConfig = options.cookieConfig;
      const sessionId = req.cookies[cookieConfig.sessionName];
      const ssoclientOptions = options.ssoClient.getClientOptions();
      const ssoSession = await options.ssoClient.session(sessionId, ssoclientOptions.appId);
      res.json({
        success: true,
        ...ssoSession
      });
    }
  });
  router.post("/refresh", async (req, res) => {
    console.log("[BigsoAuthSDK] Received /refresh request. Cookies:", req.cookies);
    console.log("[BigsoAuthSDK] headers:", req.headers);
    const cookieConfig = options.cookieConfig;
    const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
    const cookiePath = cookieConfig?.refreshPath;
    const cookieSameSite = cookieConfig ? cookieConfig.sameSite : process.env.COOKIE_SAMESITE;
    try {
      const refreshToken = req.cookies?.[cookieConfig?.refreshName];
      if (!refreshToken) {
        res.status(401).json({ error: "No refresh token available" });
        return;
      }
      let tenantId = req.headers["x-tenant-id"]?.toString() || "";
      if (!tenantId) {
        try {
          const payload = JSON.parse(Buffer.from(refreshToken.split(".")[1], "base64").toString());
          tenantId = payload["https://bigso.co/tenant_id"] || payload.tenantId || "";
          if (tenantId) {
            console.log("[BigsoAuthSDK] Recovered tenantId from refresh token JWT:", tenantId);
          }
        } catch (e) {
          console.warn("[BigsoAuthSDK] Could not parse tenantId from refresh token:", e);
        }
      }
      console.log("TENANT ANTES DE ENVIAR:", tenantId);
      const ssoResponse = await options.ssoClient.refreshTokens(refreshToken, tenantId);
      const maxAge = cookieConfig?.maxAge || 7 * 24 * 60 * 60 * 1e3;
      if (ssoResponse.tokens?.refreshToken) {
        res.cookie(cookieConfig?.refreshName, ssoResponse.tokens.refreshToken, {
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
      const currentTenant = ssoResponse.currentTenant;
      if (cookieConfig && currentTenant && currentTenant.permissions?.length > 0) {
        res.cookie(cookieConfig.permissionName, serializePermissions(currentTenant.permissions), {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieSameSite,
          path: cookieConfig.permissionPath,
          maxAge,
          domain: cookieDomain
        });
        console.log(`[BigsoAuthSDK] Refreshed permissions cookie for tenant ${currentTenant.id} with ${currentTenant.permissions.length} permissions`);
      } else if (cookieConfig) {
        console.warn("[BigsoAuthSDK] No permissions received in refresh response \u2014 permissions cookie NOT updated");
      }
      res.json({
        success: true,
        tokens: ssoResponse.tokens
      });
    } catch (error) {
      console.error("[BigsoAuthSDK] Error refreshing tokens:", error.message);
      if (error.message?.includes("revoked") || error.message?.includes("expired") || error.message?.includes("Invalid")) {
        res.clearCookie(cookieConfig?.refreshName, {
          path: cookiePath,
          domain: cookieDomain
        });
      }
      res.status(401).json({ error: error.message || "Failed to refresh tokens" });
    }
  });
  router.post("/logout", async (req, res) => {
    const accessToken = req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.substring(7) : "";
    try {
      if (accessToken) {
        await options.ssoClient.logout(accessToken, req.body?.revokeAll ?? false);
      } else {
        console.warn("[BigsoAuthSDK] Logout called without access token \u2014 skipping SSO-core revocation, clearing cookies anyway.");
      }
      if (options.onLogout) {
        await options.onLogout(accessToken);
      }
    } catch (error) {
      console.warn("[BigsoAuthSDK] Failed to logout in SSO Backend.", error.message);
    } finally {
      const cookieConfig = options.cookieConfig;
      const clearOpts = cookieConfig ? { domain: cookieConfig.domain, path: "/" } : {};
      for (const cookieName of [cookieConfig?.sessionName, cookieConfig?.refreshName, cookieConfig?.permissionName]) {
        if (cookieName) {
          res.clearCookie(cookieName, clearOpts);
        }
      }
      if (!res.headersSent) {
        res.status(200).json({ success: true, message: "Logged out" });
      }
    }
  });
  return router;
}

// src/express/routes/createSsoSyncRouter.ts
import { Router as Router2 } from "express";
function createSsoSyncRouter(options) {
  const router = Router2();
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
export {
  createSsoAuthRouter,
  createSsoSyncRouter,
  ssoAuthMiddleware,
  ssoSyncGuardMiddleware
};
