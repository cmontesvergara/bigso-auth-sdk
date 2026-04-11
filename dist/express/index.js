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
      const selectedTenantId = payload.tenantId;
      const tenantInfo = payload.tenants.find((t) => t.id === selectedTenantId);
      req.user = {
        userId: payload.sub,
        email: "",
        firstName: "",
        lastName: ""
      };
      req.tenant = tenantInfo;
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
function createSsoAuthRouter(options) {
  const router = Router();
  router.post("/exchange", async (req, res) => {
    try {
      const { code, codeVerifier } = req.body;
      if (!code || !codeVerifier) {
        res.status(400).json({ error: "code and codeVerifier are required" });
        return;
      }
      const ssoResponse = await options.ssoClient.exchangeCode(code, codeVerifier);
      if (options.onLoginSuccess) {
        await options.onLoginSuccess(ssoResponse);
      }
      res.json({
        success: true,
        tokens: ssoResponse.tokens,
        user: ssoResponse.user,
        tenant: ssoResponse.tenant
      });
    } catch (error) {
      console.error("[BigsoAuthSDK] Error exchanging code:", error.message);
      res.status(401).json({ error: error.message || "Failed to exchange authorization code" });
    }
  });
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
      if (options.onLoginSuccess) {
        await options.onLoginSuccess(ssoResponse);
      }
      res.json({
        success: true,
        tokens: ssoResponse.tokens,
        user: ssoResponse.user,
        tenant: ssoResponse.tenant
      });
    } catch (error) {
      console.error("[BigsoAuthSDK] Error exchanging v2 payload:", error.message);
      res.status(401).json({ error: error.message || "Failed to verify signed payload" });
    }
  });
  router.get("/session", ssoAuthMiddleware({ ssoClient: options.ssoClient }), (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    res.json({
      success: true,
      user: req.user,
      tenant: req.tenant,
      tokenPayload: req.tokenPayload
    });
  });
  router.post("/refresh", async (req, res) => {
    try {
      const ssoResponse = await options.ssoClient.refreshTokens();
      res.json({
        success: true,
        tokens: ssoResponse.tokens
      });
    } catch (error) {
      console.error("[BigsoAuthSDK] Error refreshing tokens:", error.message);
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
      res.json({ success: true, message: "Logged out" });
    } catch (error) {
      console.warn("[BigsoAuthSDK] Failed to logout in SSO Backend.", error.message);
      res.json({ success: true, message: "Logged out (backend revocation failed)" });
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
