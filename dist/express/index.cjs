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
  buildSessionCookieOptions: () => buildSessionCookieOptions,
  clearLegacyCookies: () => clearLegacyCookies,
  createContextualLaunchRouter: () => createContextualLaunchRouter,
  createSsoAuthRouter: () => createSsoAuthRouter,
  createSsoSyncRouter: () => createSsoSyncRouter,
  csrfGuardMiddleware: () => csrfGuardMiddleware,
  generateCsrfSecret: () => generateCsrfSecret,
  generateCsrfToken: () => generateCsrfToken,
  hostOnlyCookieOptions: () => hostOnlyCookieOptions,
  hostOnlySessionName: () => hostOnlySessionName,
  isHostOnlyConfig: () => isHostOnlyConfig,
  projectPublicAuthResponse: () => projectPublicAuthResponse,
  resolveSessionCookieNames: () => resolveSessionCookieNames,
  ssoAuthMiddleware: () => ssoAuthMiddleware,
  ssoSyncGuardMiddleware: () => ssoSyncGuardMiddleware,
  validateCsrf: () => validateCsrf
});
module.exports = __toCommonJS(express_exports);

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

// src/express/cookies/hostOnlyCookies.ts
function isHostOnlyConfig(config) {
  return !!config && config.hostOnly === true && !!config.appSlug;
}
function hostOnlySessionName(appSlug) {
  return `__Host-Http-bigso-session-${appSlug}`;
}
function hostOnlyCookieOptions(maxAge, sameSite = "strict") {
  return {
    httpOnly: true,
    secure: true,
    sameSite,
    path: "/",
    maxAge
  };
}
function clearLegacyCookies(res, legacyCookies) {
  for (const { name, domain, path = "/" } of legacyCookies) {
    if (domain) {
      res.clearCookie(name, { domain, path });
    }
    res.clearCookie(name, { path });
  }
}
function buildSessionCookieOptions(config) {
  if (isHostOnlyConfig(config)) {
    return {
      name: hostOnlySessionName(config.appSlug),
      options: hostOnlyCookieOptions(config.maxAge, config.sameSite ?? "strict")
    };
  }
  return {
    name: config.sessionName,
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: config.sameSite,
      path: config.sessionPath,
      maxAge: config.maxAge,
      domain: config.domain
    }
  };
}
function resolveSessionCookieNames(config) {
  if (isHostOnlyConfig(config)) {
    const names = /* @__PURE__ */ new Set([hostOnlySessionName(config.appSlug)]);
    for (const legacy of config.legacyCookies ?? []) {
      names.add(legacy.name);
    }
    return [...names];
  }
  return [config.sessionName];
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
      if (!accessToken && options.cookieConfig && req.cookies) {
        const sessionNames = "sessionName" in options.cookieConfig ? [options.cookieConfig.sessionName] : resolveSessionCookieNames(options.cookieConfig);
        const sessionId = sessionNames.map((name) => req.cookies[name]).find(Boolean);
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

// src/express/middlewares/csrfGuard.ts
var import_node_crypto = require("crypto");
var CSRF_HEADER = "x-csrf-token";
function normalizeOrigin(origin) {
  if (!origin) return void 0;
  try {
    return new URL(origin).origin.toLowerCase();
  } catch {
    return origin.toLowerCase();
  }
}
function approvedOrigin(origin, allowed) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;
  const allowedSet = new Set(allowed.map((o) => normalizeOrigin(o)).filter((o) => !!o));
  return allowedSet.has(normalized);
}
function generateCsrfToken(sessionHandle, sessionSecret) {
  return (0, import_node_crypto.createHash)("sha256").update(`${sessionSecret}:${sessionHandle}:${sessionSecret}`).digest("base64url").slice(0, 32);
}
function generateCsrfSecret() {
  return (0, import_node_crypto.randomBytes)(32).toString("base64url");
}
function validateCsrf(req, options) {
  const method = req.method?.toUpperCase() ?? "";
  if (["GET", "HEAD", "OPTIONS", "TRACE"].includes(method)) {
    return { ok: true };
  }
  if (options.skipIf?.(req)) {
    return { ok: true };
  }
  const origin = req.headers.origin;
  if (!approvedOrigin(origin, options.allowedOrigins)) {
    return { ok: false, reason: "origin_mismatch" };
  }
  if (options.requireSameSiteFetch) {
    const secFetchSite = req.headers["sec-fetch-site"];
    if (secFetchSite && secFetchSite.toLowerCase() !== "same-origin") {
      return { ok: false, reason: "sec_fetch_site_mismatch" };
    }
  }
  const headerToken = req.headers[CSRF_HEADER]?.trim();
  if (!headerToken) {
    return { ok: false, reason: "missing_header" };
  }
  const sessionToken = options.getSessionCsrfToken(req);
  if (!sessionToken || headerToken !== sessionToken) {
    return { ok: false, reason: "token_mismatch" };
  }
  return { ok: true };
}
function csrfGuardMiddleware(options) {
  const allowedOrigins = options.allowedOrigins.map((o) => o.trim()).filter(Boolean);
  return (req, res, next) => {
    const result = validateCsrf(req, { ...options, allowedOrigins });
    if (result.ok) {
      next();
      return;
    }
    res.status(403).json({ error: "csrf_or_origin_mismatch" });
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
var import_express = require("express");
var import_node_crypto2 = require("crypto");

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
  return (0, import_node_crypto2.createHash)("sha256").update(token).digest("base64url");
}
function serializePermissions(permissions) {
  return permissions.map((p) => `${p.resource}:${p.action}`).join(",");
}
function createSsoAuthRouter(options) {
  const router = (0, import_express.Router)();
  if (options.hostOnlyCookies && !options.appSlug) {
    throw new Error("appSlug is required when hostOnlyCookies is enabled");
  }
  const effectiveCookieConfig = options.cookieConfig ? options.hostOnlyCookies && options.appSlug ? { ...options.cookieConfig, hostOnly: true, appSlug: options.appSlug } : options.cookieConfig : void 0;
  const sessionCookieNames = effectiveCookieConfig ? resolveSessionCookieNames(effectiveCookieConfig) : [];
  const csrfSecret = options.csrfSecret ?? generateCsrfSecret();
  function deriveCsrfToken(sessionHandle) {
    return generateCsrfToken(sessionHandle, csrfSecret);
  }
  function getSessionHandleFromCookies(req) {
    if (!effectiveCookieConfig || !req.cookies) return void 0;
    for (const name of sessionCookieNames) {
      const value = req.cookies[name];
      if (value) return value;
    }
    return void 0;
  }
  function setHostOnlySessionCookie(res, sessionHandle, maxAge) {
    if (!effectiveCookieConfig || !isHostOnlyConfig(effectiveCookieConfig)) return;
    const { name, options: options2 } = buildSessionCookieOptions(effectiveCookieConfig);
    res.cookie(name, sessionHandle, options2);
  }
  function clearAuthCookies(res) {
    if (!effectiveCookieConfig) return;
    if (isHostOnlyConfig(effectiveCookieConfig)) {
      const { name, options: options2 } = buildSessionCookieOptions(effectiveCookieConfig);
      res.clearCookie(name, { path: options2.path });
      clearLegacyCookies(res, effectiveCookieConfig.legacyCookies ?? []);
    } else {
      const cookieConfig = effectiveCookieConfig;
      res.clearCookie(cookieConfig.sessionName, { domain: cookieConfig.domain, path: cookieConfig.sessionPath });
      res.clearCookie(cookieConfig.refreshName, { domain: cookieConfig.domain, path: cookieConfig.refreshPath });
      res.clearCookie(cookieConfig.permissionName, { domain: cookieConfig.domain, path: cookieConfig.permissionPath });
    }
  }
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
      const opaqueSessionHandle = ssoResponse.sessionId ?? ssoResponse.tokens.jti;
      if (effectiveCookieConfig && opaqueSessionHandle) {
        if (isHostOnlyConfig(effectiveCookieConfig)) {
          logger2.info("Establishing host-only application session cookie");
          setHostOnlySessionCookie(res, opaqueSessionHandle, effectiveCookieConfig.maxAge);
          clearLegacyCookies(res, effectiveCookieConfig.legacyCookies ?? []);
        } else {
          logger2.info("Establishing legacy application session cookies");
          const cookieConfig = effectiveCookieConfig;
          res.cookie(cookieConfig.sessionName, opaqueSessionHandle, {
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
      }
      if (options.onLoginSuccess) {
        await options.onLoginSuccess(ssoResponse);
      }
      res.json(projectPublicAuthResponse({
        ...ssoResponse,
        ...effectiveCookieConfig && isHostOnlyConfig(effectiveCookieConfig) && opaqueSessionHandle ? { csrfToken: deriveCsrfToken(opaqueSessionHandle) } : {}
      }));
    } catch (error) {
      logger2.error("Authentication exchange failed", { errorType: error?.name ?? "UnknownError" });
      res.status(401).json({ error: "exchange_failed" });
    }
  });
  router.get("/session", async (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    if (effectiveCookieConfig) {
      logger2.info("Resolving application session");
      const sessionHandle = getSessionHandleFromCookies(req);
      if (!sessionHandle) {
        res.status(401).json({ error: "session_required" });
        return;
      }
      const ssoclientOptions = options.ssoClient.getClientOptions();
      const ssoSession = await options.ssoClient.session(sessionHandle, ssoclientOptions.appId);
      res.json(projectPublicAuthResponse({
        success: true,
        ...ssoSession,
        ...isHostOnlyConfig(effectiveCookieConfig) ? { csrfToken: deriveCsrfToken(sessionHandle) } : {}
      }));
    }
  });
  router.post("/refresh", async (req, res) => {
    if (effectiveCookieConfig && isHostOnlyConfig(effectiveCookieConfig)) {
      logger2.info("Host-only refresh route invoked");
      const sessionHandle = getSessionHandleFromCookies(req);
      if (!sessionHandle) {
        res.status(401).json({ error: "session_required" });
        return;
      }
      const ssoclientOptions = options.ssoClient.getClientOptions();
      const ssoSession = await options.ssoClient.session(sessionHandle, ssoclientOptions.appId);
      res.json(projectPublicAuthResponse({
        success: true,
        ...ssoSession,
        csrfToken: deriveCsrfToken(sessionHandle)
      }));
      return;
    }
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
    if (!tenantId || !effectiveCookieConfig) {
      res.status(400).json({ error: "invalid_tenant_switch_request" });
      return;
    }
    const verifier = (0, import_node_crypto2.randomBytes)(32).toString("base64url");
    const challenge = (0, import_node_crypto2.createHash)("sha256").update(verifier).digest("base64url");
    try {
      if (!accessToken) {
        const sessionHandle = getSessionHandleFromCookies(req);
        if (!sessionHandle) {
          res.status(401).json({ error: "tenant_switch_session_required" });
          return;
        }
        const current = await options.ssoClient.session(
          sessionHandle,
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
        state: (0, import_node_crypto2.randomUUID)()
      });
      const session = await options.ssoClient.exchangeCode(authorization.code, verifier);
      const opaqueSessionHandle = session.sessionId ?? session.tokens.jti;
      if (isHostOnlyConfig(effectiveCookieConfig) && opaqueSessionHandle) {
        setHostOnlySessionCookie(res, opaqueSessionHandle, effectiveCookieConfig.maxAge);
        clearLegacyCookies(res, effectiveCookieConfig.legacyCookies ?? []);
      } else {
        const cookie = effectiveCookieConfig;
        const base = { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: cookie.sameSite, maxAge: cookie.maxAge, domain: cookie.domain };
        res.cookie(cookie.sessionName, opaqueSessionHandle, { ...base, path: cookie.sessionPath });
        res.cookie(cookie.refreshName, session.tokens.refreshToken, { ...base, path: cookie.refreshPath });
        res.cookie(cookie.permissionName, serializePermissions(session.currentTenant.permissions), { ...base, path: cookie.permissionPath });
      }
      if (options.onLoginSuccess) await options.onLoginSuccess(session);
      res.status(200).json(projectPublicAuthResponse({
        ...session,
        ...isHostOnlyConfig(effectiveCookieConfig) && opaqueSessionHandle ? { csrfToken: deriveCsrfToken(opaqueSessionHandle) } : {}
      }));
    } catch (error) {
      clearAuthCookies(res);
      logger2.warn("Tenant session replacement failed", { errorType: error?.name ?? "UnknownError" });
      res.status(401).json({ error: "tenant_switch_failed" });
    }
  });
  router.post("/logout", async (req, res) => {
    let accessToken = req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.substring(7) : "";
    const scope = req.body?.scope ?? (req.body?.revokeAll ? "global" : "application");
    if (scope !== "application" && scope !== "global") {
      res.status(400).json({ error: "unsupported_logout_scope" });
      return;
    }
    let revocationSucceeded = true;
    try {
      if (!accessToken && effectiveCookieConfig) {
        const sessionHandle = getSessionHandleFromCookies(req);
        if (sessionHandle) {
          const current = await options.ssoClient.session(
            sessionHandle,
            options.ssoClient.getClientOptions().appId
          );
          accessToken = current?.tokens?.accessToken ?? current?.accessToken ?? "";
        }
      }
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
      clearAuthCookies(res);
      if (!res.headersSent) {
        if (scope === "global" && (!revocationSucceeded || !options.identityLogoutUrl)) {
          res.status(502).json({ error: "global_logout_unavailable" });
          return;
        }
        if (scope === "global") {
          const state = (0, import_node_crypto2.randomUUID)();
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
      console.error("[BigsoAuthSDK] Sync endpoint failed", {
        errorType: error?.name ?? "UnknownError"
      });
      res.status(500).json({ error: "resource_sync_failed" });
    }
  });
  return router;
}

// src/express/routes/createContextualLaunchRouter.ts
var import_express3 = require("express");
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function createContextualLaunchRouter(options) {
  const router = (0, import_express3.Router)();
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  buildSessionCookieOptions,
  clearLegacyCookies,
  createContextualLaunchRouter,
  createSsoAuthRouter,
  createSsoSyncRouter,
  csrfGuardMiddleware,
  generateCsrfSecret,
  generateCsrfToken,
  hostOnlyCookieOptions,
  hostOnlySessionName,
  isHostOnlyConfig,
  projectPublicAuthResponse,
  resolveSessionCookieNames,
  ssoAuthMiddleware,
  ssoSyncGuardMiddleware,
  validateCsrf
});
