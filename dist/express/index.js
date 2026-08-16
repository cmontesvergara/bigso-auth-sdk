// src/utils/logger.ts
var SdkLogger = class {
  constructor(context) {
    this.context = context;
  }
  format(level, message, meta) {
    const ts = (/* @__PURE__ */ new Date()).toISOString();
    const metaStr = meta ? " | " + JSON.stringify(redact(meta)) : "";
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
var sensitiveKey = /(authorization|cookie|password|secret|token|payload|hash|verifier|challenge)/i;
var jwtValue = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
var bearerValue = /Bearer\s+[^\s,;]+/gi;
function redact(value, key) {
  if (key && sensitiveKey.test(key)) return "[REDACTED]";
  if (typeof value === "string") {
    return value.replace(jwtValue, "[REDACTED]").replace(bearerValue, "Bearer [REDACTED]");
  }
  if (Array.isArray(value)) return value.map((item) => redact(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([nestedKey, nestedValue]) => [nestedKey, redact(nestedValue, nestedKey)])
    );
  }
  return value;
}

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
          logger.info("Resolving authentication from application session");
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
      logger.error("Authentication middleware failed", {
        errorType: error instanceof Error ? error.name : "UnknownError"
      });
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
        console.warn("[BigsoAuthSDK] Blocked sync request from unauthorized origin");
        res.status(403).json({ error: "Unauthorized origin" });
        return;
      }
      next();
    } catch (error) {
      console.error("[BigsoAuthSDK] Sync guard validation failed", {
        errorType: error instanceof Error ? error.name : "UnknownError"
      });
      res.status(500).json({ error: "Security validation failed" });
    }
  };
}

// src/express/routes/createSsoAuthRouter.ts
import { Router } from "express";
import { createHash, randomBytes, randomUUID } from "crypto";

// src/express/publicAuthResponse.ts
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function stringValue(record, key) {
  return typeof record[key] === "string" ? record[key] : void 0;
}
function projectUser(value) {
  if (!isRecord(value)) return void 0;
  const userId = stringValue(value, "userId") ?? stringValue(value, "id");
  const email = stringValue(value, "email");
  if (!userId || !email) return void 0;
  return {
    userId,
    email,
    firstName: stringValue(value, "firstName") ?? "",
    lastName: stringValue(value, "lastName") ?? ""
  };
}
function projectPermissions(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((permission) => {
    if (!isRecord(permission)) return [];
    const resource = stringValue(permission, "resource");
    const action = stringValue(permission, "action");
    return resource && action ? [{ resource, action }] : [];
  });
}
function projectTenant(value) {
  if (!isRecord(value)) return void 0;
  const id = stringValue(value, "id");
  if (!id) return void 0;
  return {
    id,
    name: stringValue(value, "name") ?? "",
    slug: stringValue(value, "slug") ?? "",
    role: stringValue(value, "role") ?? "",
    permissions: projectPermissions(value.permissions)
  };
}
function projectApplication(value) {
  if (!isRecord(value)) return void 0;
  const appId = stringValue(value, "appId");
  const name = stringValue(value, "name");
  if (!appId || !name) return void 0;
  return {
    appId,
    name,
    logoUrl: stringValue(value, "logoUrl") ?? null
  };
}
function projectPublicAuthResponse(value) {
  const input = isRecord(value) ? value : {};
  const tokens = isRecord(input.tokens) ? input.tokens : {};
  const expiresIn = typeof tokens.expiresIn === "number" ? tokens.expiresIn : typeof input.expiresIn === "number" ? input.expiresIn : void 0;
  const user = projectUser(input.user);
  const currentTenant = projectTenant(input.currentTenant);
  const relatedTenants = Array.isArray(input.relatedTenants) ? input.relatedTenants.flatMap((tenant) => projectTenant(tenant) ?? []) : void 0;
  const activeApplications = Array.isArray(input.activeApplications) ? input.activeApplications.flatMap((application) => projectApplication(application) ?? []) : void 0;
  const csrfToken = stringValue(input, "csrfToken");
  return {
    success: input.success !== false,
    ...expiresIn === void 0 ? {} : { expiresIn },
    ...user ? { user } : {},
    ...currentTenant ? { currentTenant } : {},
    ...relatedTenants ? { relatedTenants } : {},
    ...activeApplications ? { activeApplications } : {},
    ...csrfToken ? { csrfToken } : {}
  };
}

// src/express/routes/createSsoAuthRouter.ts
var logger2 = new SdkLogger("AuthSDK");
var activeRefreshes = /* @__PURE__ */ new Map();
function getRefreshKey(token) {
  return createHash("sha256").update(token).digest("base64url");
}
function serializePermissions(permissions) {
  return permissions.map((p) => `${p.resource}:${p.action}`).join(",");
}
function createSsoAuthRouter(options) {
  const router = Router();
  router.post("/exchange", async (req, res) => {
    logger2.info("Received authentication exchange request");
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
        logger2.info("Establishing application session cookies");
        const cookieConfig = options.cookieConfig;
        res.cookie(cookieConfig.sessionName, ssoResponse.sessionId ?? ssoResponse.tokens.jti, {
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
      res.json(projectPublicAuthResponse(ssoResponse));
    } catch (error) {
      logger2.error("Authentication exchange failed", { errorType: error?.name ?? "UnknownError" });
      res.status(401).json({ error: "exchange_failed" });
    }
  });
  router.get("/session", async (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    if (options.cookieConfig) {
      logger2.info("Resolving application session");
      const cookieConfig = options.cookieConfig;
      const sessionId = req.cookies[cookieConfig.sessionName];
      const ssoclientOptions = options.ssoClient.getClientOptions();
      const ssoSession = await options.ssoClient.session(sessionId, ssoclientOptions.appId);
      res.json(projectPublicAuthResponse({ success: true, ...ssoSession }));
    }
  });
  router.post("/refresh", async (req, res) => {
    const cookieConfig = options.cookieConfig;
    const refreshName = cookieConfig?.refreshName;
    const incomingToken = req.cookies?.[refreshName];
    logger2.info("Received refresh request", {
      hasSessionCredential: !!incomingToken
    });
    const cookieDomain = cookieConfig ? cookieConfig.domain : process.env.COOKIE_DOMAIN;
    const cookiePath = cookieConfig?.refreshPath;
    const cookieSameSite = cookieConfig ? cookieConfig.sameSite : process.env.COOKIE_SAMESITE;
    try {
      const refreshToken = req.cookies?.[cookieConfig?.refreshName];
      if (!refreshToken) {
        logger2.warn("No refresh credential available");
        res.status(401).json({ error: "No refresh token available" });
        return;
      }
      let tenantId;
      try {
        const payload = JSON.parse(Buffer.from(refreshToken.split(".")[1], "base64").toString());
        tenantId = payload["https://bigso.org/tenant_id"] || payload["https://bigso.co/tenant_id"] || payload.tenantId || "";
        if (tenantId) {
          logger2.info("Recovered tenant context from refresh credential");
        }
      } catch {
        logger2.warn("Could not resolve tenant context from refresh credential");
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
        logger2.info("Refresh already in flight, waiting for result");
      }
      const ssoResponse = await refreshPromise;
      const maxAge = cookieConfig?.maxAge || 7 * 24 * 60 * 60 * 1e3;
      const opaqueSessionHandle = ssoResponse.sessionId ?? ssoResponse.tokens?.jti;
      if (cookieConfig && opaqueSessionHandle) {
        res.cookie(cookieConfig.sessionName, opaqueSessionHandle, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: cookieSameSite,
          path: cookieConfig.sessionPath,
          maxAge,
          domain: cookieDomain
        });
        logger2.info("Session cookie rotated after refresh");
      }
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
        logger2.info("Refresh credential cookie rotated");
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
      res.json(projectPublicAuthResponse(ssoResponse));
    } catch (error) {
      logger2.error("Token refresh failed", { errorType: error?.name ?? "UnknownError" });
      const isAuthError = error?.status === 401 || error?.status === 403 || error.message?.includes("revoked") || error.message?.includes("expired") || error.message?.includes("Invalid") || error.message?.includes("not recognized") || error.message?.includes("Token not found") || error.message?.includes("reuse detected");
      if (isAuthError) {
        res.clearCookie(cookieConfig?.refreshName, {
          path: cookiePath,
          domain: cookieDomain
        });
        logger2.info("Cleared invalid refresh credential cookie");
      }
      res.status(401).json({ error: "refresh_failed" });
    }
  });
  router.post("/tenant-context", async (req, res) => {
    let accessToken = req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.substring(7) : "";
    const tenantId = typeof req.body?.tenantId === "string" ? req.body.tenantId : "";
    if (!tenantId || !options.cookieConfig) {
      res.status(400).json({ error: "invalid_tenant_switch_request" });
      return;
    }
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    try {
      if (!accessToken) {
        const sessionId = req.cookies?.[options.cookieConfig.sessionName];
        if (!sessionId) {
          res.status(401).json({ error: "tenant_switch_session_required" });
          return;
        }
        const current = await options.ssoClient.session(
          sessionId,
          options.ssoClient.getClientOptions().appId
        );
        accessToken = current?.tokens?.accessToken ?? current?.accessToken ?? "";
        if (!accessToken) {
          res.status(401).json({ error: "tenant_switch_session_required" });
          return;
        }
      }
      const authorization = await options.ssoClient.authorizeTenant({
        accessToken,
        tenantId,
        redirectUri: options.tenantSwitchRedirectUri ?? `${options.frontendUrl.replace(/\/$/, "")}/launch`,
        codeChallenge: challenge,
        state: randomUUID()
      });
      const session = await options.ssoClient.exchangeCode(authorization.code, verifier);
      const cookie = options.cookieConfig;
      const base = { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: cookie.sameSite, maxAge: cookie.maxAge, domain: cookie.domain };
      res.cookie(cookie.sessionName, session.sessionId ?? session.tokens.jti, { ...base, path: cookie.sessionPath });
      res.cookie(cookie.refreshName, session.tokens.refreshToken, { ...base, path: cookie.refreshPath });
      res.cookie(cookie.permissionName, serializePermissions(session.currentTenant.permissions), { ...base, path: cookie.permissionPath });
      if (options.onLoginSuccess) await options.onLoginSuccess(session);
      res.status(200).json(projectPublicAuthResponse(session));
    } catch (error) {
      const cookie = options.cookieConfig;
      for (const [name, path] of [[cookie.sessionName, cookie.sessionPath], [cookie.refreshName, cookie.refreshPath], [cookie.permissionName, cookie.permissionPath]]) {
        res.clearCookie(name, { domain: cookie.domain, path });
      }
      logger2.warn("Tenant session replacement failed", { errorType: error?.name ?? "UnknownError" });
      res.status(401).json({ error: "tenant_switch_failed" });
    }
  });
  router.post("/logout", async (req, res) => {
    const accessToken = req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.substring(7) : "";
    const scope = req.body?.scope ?? (req.body?.revokeAll ? "global" : "application");
    if (scope !== "application" && scope !== "global") {
      res.status(400).json({ error: "unsupported_logout_scope" });
      return;
    }
    let revocationSucceeded = true;
    try {
      if (accessToken) {
        await options.ssoClient.logout(accessToken, { scope });
      } else {
        logger2.warn("Logout called without access token \u2014 skipping SSO-core revocation, clearing cookies anyway.");
        if (scope === "global") revocationSucceeded = false;
      }
      if (options.onLogout) {
        await options.onLogout(accessToken);
      }
    } catch (error) {
      revocationSucceeded = false;
      logger2.warn("Failed to logout in SSO Backend", { errorType: error?.name ?? "UnknownError" });
    } finally {
      const cookieConfig = options.cookieConfig;
      const clearOpts = cookieConfig ? { domain: cookieConfig.domain, path: "/" } : {};
      for (const cookieName of [cookieConfig?.sessionName, cookieConfig?.refreshName, cookieConfig?.permissionName]) {
        if (cookieName) {
          res.clearCookie(cookieName, clearOpts);
        }
      }
      if (!res.headersSent) {
        if (scope === "global" && (!revocationSucceeded || !options.identityLogoutUrl)) {
          res.status(502).json({ error: "global_logout_unavailable" });
          return;
        }
        if (scope === "global") {
          const state = randomUUID();
          const continuation = new URL(options.identityLogoutUrl);
          continuation.searchParams.set("app_id", options.ssoClient.getClientOptions().appId);
          continuation.searchParams.set(
            "return_uri",
            options.logoutReturnUri ?? `${options.frontendUrl.replace(/\/$/, "")}/launch`
          );
          continuation.searchParams.set("state", state);
          continuation.searchParams.set("transition", "bigso-overlay-v1");
          res.status(200).json({
            success: true,
            scope,
            continueUrl: continuation.toString(),
            state
          });
          return;
        }
        res.status(200).json({ success: true, scope });
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
      console.error("[BigsoAuthSDK] Sync endpoint failed", {
        errorType: error?.name ?? "UnknownError"
      });
      res.status(500).json({ error: "resource_sync_failed" });
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
  projectPublicAuthResponse,
  ssoAuthMiddleware,
  ssoSyncGuardMiddleware
};
