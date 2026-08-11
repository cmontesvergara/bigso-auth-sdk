// src/utils/logger.ts
var SdkLogger = class {
  constructor(context) {
    this.context = context;
  }
  format(level, message, meta) {
    const ts = (/* @__PURE__ */ new Date()).toISOString();
    const metaStr = meta ? " | " + JSON.stringify(meta) : "";
    return `[${ts}] [${level}] [${this.context}] ${message}${metaStr}`;
  }
  info(message, meta) {
    console.log(this.format("INFO", message, meta));
  }
  warn(message, meta) {
    console.warn(this.format("WARN", message, meta));
  }
  error(message, meta) {
    console.error(this.format("ERROR", message, meta));
  }
};

// src/express/middlewares/ssoAuth.ts
var logger = new SdkLogger("AuthSDK");
function ssoAuthMiddleware(options) {
  return async (req, res, next) => {
    try {
      let accessToken;
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith("Bearer ")) {
        accessToken = authHeader.substring(7);
      }
      if (!accessToken && options.cookieConfig?.sessionName && req.cookies) {
        const sessionId = req.cookies[options.cookieConfig.sessionName];
        if (sessionId) {
          logger.info("No Bearer header, falling back to session cookie", {
            sessionName: options.cookieConfig.sessionName
          });
          const ssoClientOptions = options.ssoClient.getClientOptions();
          const session = await options.ssoClient.session(sessionId, ssoClientOptions.appId);
          accessToken = session?.tokens?.accessToken;
        }
      }
      if (!accessToken) {
        res.status(401).json({ error: "Missing access token" });
        return;
      }
      const payload = await options.ssoClient.validateAccessToken(accessToken);
      if (!payload) {
        res.status(401).json({ error: "Invalid or expired access token" });
        return;
      }
      req.tokenPayload = payload;
      next();
    } catch (error) {
      logger.error("Authentication Middleware Error", { message: error instanceof Error ? error.message : String(error) });
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
var logger2 = new SdkLogger("AuthSDK");
var activeRefreshes = /* @__PURE__ */ new Map();
function getRefreshKey(token) {
  return token.substring(0, 20);
}
function serializePermissions(permissions) {
  return permissions.map((p) => `${p.resource}:${p.action}`).join(",");
}
function createSsoAuthRouter(options) {
  const router = Router();
  router.post("/exchange", async (req, res) => {
    logger2.info("Received /exchange-v2 request", { body: req.body });
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
        logger2.info("Setting refresh token cookie with custom config", { config: options.cookieConfig });
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
      logger2.error("Error exchanging v2 payload", { message: error.message });
      res.status(401).json({ error: error.message || "Failed to verify signed payload" });
    }
  });
  router.get("/session", async (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    if (options.cookieConfig) {
      logger2.info("Session request", { config: options.cookieConfig });
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
    const cookieConfig = options.cookieConfig;
    const refreshName = cookieConfig?.refreshName;
    const incomingToken = req.cookies?.[refreshName];
    logger2.info("Received /refresh request", {
      refreshName,
      hasCookie: !!incomingToken,
      tokenPrefix: incomingToken ? incomingToken.substring(0, 20) : null,
      tenantId: req.headers["x-tenant-id"]
    });
    const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
    const cookiePath = cookieConfig?.refreshPath;
    const cookieSameSite = cookieConfig ? cookieConfig.sameSite : process.env.COOKIE_SAMESITE;
    try {
      const refreshToken = req.cookies?.[cookieConfig?.refreshName];
      if (!refreshToken) {
        logger2.warn("No refresh token in cookies", { refreshName });
        res.status(401).json({ error: "No refresh token available" });
        return;
      }
      let tenantId = req.headers["x-tenant-id"]?.toString() || void 0;
      if (!tenantId) {
        try {
          const payload = JSON.parse(Buffer.from(refreshToken.split(".")[1], "base64").toString());
          tenantId = payload["https://bigso.org/tenant_id"] || payload["https://bigso.co/tenant_id"] || payload.tenantId || "";
          if (tenantId) {
            logger2.info("Recovered tenantId from refresh token JWT", { tenantId });
          }
        } catch (e) {
          logger2.warn("Could not parse tenantId from refresh token", { error: e.message });
        }
      }
      logger2.info("Forwarding refresh to IDP", { tenantId: tenantId || "(empty)" });
      const refreshKey = getRefreshKey(refreshToken);
      let refreshPromise = activeRefreshes.get(refreshKey);
      if (!refreshPromise) {
        refreshPromise = options.ssoClient.refreshTokens(refreshToken, tenantId).catch((err) => {
          activeRefreshes.delete(refreshKey);
          throw err;
        });
        activeRefreshes.set(refreshKey, refreshPromise);
        refreshPromise.then(() => {
          activeRefreshes.delete(refreshKey);
        }).catch(() => {
        });
      } else {
        logger2.info("Refresh already in flight, waiting for result", { refreshKey });
      }
      const ssoResponse = await refreshPromise;
      const maxAge = cookieConfig?.maxAge || 7 * 24 * 60 * 60 * 1e3;
      if (ssoResponse.tokens?.refreshToken) {
        const newToken = ssoResponse.tokens.refreshToken;
        res.cookie(cookieConfig?.refreshName, newToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieSameSite,
          path: cookiePath,
          maxAge,
          domain: cookieDomain
        });
        logger2.info("Cookie updated after refresh", {
          refreshName,
          oldTokenPrefix: refreshToken.substring(0, 20),
          newTokenPrefix: newToken.substring(0, 20)
        });
      } else {
        logger2.warn("No refresh token received in refresh response, not setting cookie");
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
        logger2.info("Refreshed permissions cookie", { tenantId: currentTenant.id, count: currentTenant.permissions.length });
      } else if (cookieConfig) {
        logger2.warn("No permissions received in refresh response \u2014 permissions cookie NOT updated");
      }
      res.json({
        success: true,
        tokens: ssoResponse.tokens
      });
    } catch (error) {
      logger2.error("Error refreshing tokens", { message: error.message });
      const isAuthError = error.message?.includes("revoked") || error.message?.includes("expired") || error.message?.includes("Invalid") || error.message?.includes("not recognized") || error.message?.includes("Token not found") || error.message?.includes("reuse detected");
      if (isAuthError) {
        res.clearCookie(cookieConfig?.refreshName, {
          path: cookiePath,
          domain: cookieDomain
        });
        logger2.info("Cleared invalid refresh token cookie", { refreshName, reason: error.message });
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
        logger2.warn("Logout called without access token \u2014 skipping SSO-core revocation, clearing cookies anyway.");
      }
      if (options.onLogout) {
        await options.onLogout(accessToken);
      }
    } catch (error) {
      logger2.warn("Failed to logout in SSO Backend", { message: error.message });
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

// src/express/routes/createContextualLaunchRouter.ts
import { Router as Router3 } from "express";
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function createContextualLaunchRouter(options) {
  const router = Router3();
  router.get("/session", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const tenantHint = typeof req.query.tenant_hint === "string" ? req.query.tenant_hint : "";
    if (!UUID.test(tenantHint)) {
      res.status(400).json({ reusable: false, error: "invalid_launch_context" });
      return;
    }
    const sessionId = req.cookies?.[options.cookieConfig.sessionName];
    if (!sessionId) {
      res.status(200).json({ reusable: false, error: "session_required" });
      return;
    }
    try {
      const client = options.ssoClient.getClientOptions();
      const session = await options.ssoClient.session(sessionId, client.appId);
      res.status(200).json({ reusable: session.currentTenant?.id === tenantHint });
    } catch {
      res.status(200).json({ reusable: false, error: "session_required" });
    }
  });
  return router;
}
export {
  createContextualLaunchRouter,
  createSsoAuthRouter,
  createSsoSyncRouter,
  ssoAuthMiddleware,
  ssoSyncGuardMiddleware
};
