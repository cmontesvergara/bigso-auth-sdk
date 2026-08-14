import {
  verifySignedPayload
} from "../chunk-BSPSXDAQ.js";

// src/utils/crypto.ts
async function sha256Base64Url(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64Url(new Uint8Array(digest));
}
function generateVerifier(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return base64Url(array);
}
function base64Url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function generateRandomId() {
  return crypto.randomUUID();
}

// src/utils/events.ts
var EventEmitter = class {
  constructor() {
    this.events = {};
  }
  on(event, handler) {
    if (!this.events[event]) this.events[event] = [];
    this.events[event].push(handler);
  }
  off(event, handler) {
    if (!this.events[event]) return;
    this.events[event] = this.events[event].filter((h) => h !== handler);
  }
  emit(event, data) {
    this.events[event]?.forEach((fn) => fn(data));
  }
};

// src/browser/urls.ts
function buildSsoFrameUrl(ssoOrigin, clientId, tenantId) {
  const url = new URL("/auth/i-sign-in", ssoOrigin);
  url.searchParams.set("v", "2.3");
  url.searchParams.set("client_id", clientId);
  if (tenantId) url.searchParams.set("tenant_id", tenantId);
  return url.toString();
}

// src/browser/auth.ts
var BigsoAuth = class extends EventEmitter {
  constructor(options) {
    super();
    this.authCompleted = false;
    this.requestId = generateRandomId();
    this.loginInProgress = false;
    this.options = {
      timeout: 5e3,
      debug: false,
      redirectUri: "",
      theme: "light",
      ...options
    };
  }
  async login() {
    if (this.loginInProgress) {
      this.debug("login() ya en curso, ignorando llamada duplicada");
      return Promise.reject(new Error("Login already in progress"));
    }
    this.loginInProgress = true;
    this.authCompleted = false;
    const state = generateRandomId();
    const nonce = generateRandomId();
    const verifier = generateVerifier();
    const requestId = this.requestId;
    const codeChallenge = await sha256Base64Url(verifier);
    sessionStorage.setItem("sso_ctx", JSON.stringify({ state, nonce, verifier, requestId }));
    this.createUI();
    return new Promise((resolve, reject) => {
      this.abortController = new AbortController();
      const { signal } = this.abortController;
      const cleanup = () => {
        if (this.timeoutId) clearTimeout(this.timeoutId);
        if (this.messageListener) window.removeEventListener("message", this.messageListener);
        this.iframe?.remove();
        this.iframe = void 0;
        this.authCompleted = true;
        this.loginInProgress = false;
      };
      this.messageListener = async (event) => {
        if (event.origin !== this.options.ssoOrigin) {
          this.debug("Ignorado mensaje de origen no autorizado:", event.origin);
          return;
        }
        const msg = event.data;
        this.debug("Mensaje recibido:", msg);
        if (msg.requestId && msg.requestId !== requestId) {
          this.debug("requestId no coincide, ignorado");
          return;
        }
        if (msg.type === "sso-ready") {
          this.debug("sso-ready recibido, iniciando timeout y enviando sso-init");
          this.timeoutId = window.setTimeout(() => {
            if (!this.authCompleted) {
              this.debug("Timeout alcanzado, activando fallback");
              this.closeUI();
              cleanup();
              this.emit("fallback");
              window.location.href = this.buildFallbackUrl(codeChallenge, state);
              reject(new Error("Timeout"));
            }
          }, this.options.timeout);
          let isValidTenantId = true;
          if (this.options.tenantId) {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(this.options.tenantId)) {
              isValidTenantId = false;
              this.debug("tenantId proporcionado no es un UUID v\xE1lido:", this.options.tenantId);
            }
          }
          const initPayload = {
            state,
            nonce,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            origin: window.location.origin,
            ...this.options.redirectUri && { redirect_uri: this.options.redirectUri },
            tenantId: isValidTenantId ? this.options.tenantId : void 0,
            timeout_ms: this.options.timeout
          };
          this.iframe?.contentWindow?.postMessage({
            v: "2.3",
            source: "@app/widget",
            type: "sso-init",
            requestId: this.requestId,
            payload: initPayload
          }, this.options.ssoOrigin);
          this.emit("ready");
          return;
        }
        if (msg.type === "sso-success") {
          this.debug("sso-success recibido");
          clearTimeout(this.timeoutId);
          try {
            const payload = msg.payload;
            const ctx = JSON.parse(sessionStorage.getItem("sso_ctx") || "{}");
            if (payload.state !== ctx.state) {
              throw new Error("Invalid state");
            }
            const decoded = await verifySignedPayload(
              payload.signed_payload,
              this.options.jwksUrl,
              this.options.audience ?? window.location.origin
            );
            if (decoded.nonce !== ctx.nonce) {
              throw new Error("Invalid nonce");
            }
            this.debug("JWS v\xE1lido, payload:", decoded);
            this.closeUI();
            cleanup();
            const result = {
              code: decoded.code,
              state: decoded.state || ctx.state,
              nonce: ctx.nonce,
              codeVerifier: ctx.verifier,
              signed_payload: payload.signed_payload,
              tenant: decoded.tenant,
              jti: decoded.jti,
              iss: decoded.iss,
              aud: typeof decoded.aud === "string" ? decoded.aud : void 0,
              exp: decoded.exp,
              iat: decoded.iat
            };
            this.emit("success", result);
            resolve(result);
          } catch (err) {
            this.debug("Error en sso-success:", err);
            this.closeUI();
            cleanup();
            this.emit("error", err);
            reject(err);
          }
          return;
        }
        if (msg.type === "sso-error") {
          const errorPayload = msg.payload;
          this.debug("sso-error recibido:", errorPayload);
          clearTimeout(this.timeoutId);
          this.closeUI();
          cleanup();
          if (errorPayload.code === "version_mismatch") {
            this.emit("error", errorPayload);
            window.location.href = this.buildFallbackUrl(codeChallenge, state);
            reject(new Error(`Version mismatch: expected ${errorPayload.expected_version}`));
          } else {
            this.emit("error", errorPayload);
            reject(errorPayload);
          }
        }
        if (msg.type === "sso-close") {
          this.debug("sso-close recibido");
          this.closeUI();
          cleanup();
          reject(new Error("Login cancelled by user"));
        }
      };
      window.addEventListener("message", this.messageListener);
      signal.addEventListener("abort", () => {
        this.debug("Operaci\xF3n abortada");
        this.closeUI();
        cleanup();
        reject(new Error("Login aborted"));
      });
    });
  }
  abort() {
    this.abortController?.abort();
  }
  // ─── UI Management ───────────────────────────────────────────────
  createUI() {
    if (!this.hostEl) {
      this.hostEl = document.createElement("div");
      this.hostEl.id = "bigso-auth-host";
      this.shadowRoot = this.hostEl.attachShadow({ mode: "open" });
      const style = document.createElement("style");
      style.textContent = this.getOverlayStyles();
      this.shadowRoot.appendChild(style);
      this.overlayEl = document.createElement("div");
      this.overlayEl.className = "sso-overlay";
      const closeBtn = document.createElement("button");
      closeBtn.className = "sso-close-btn";
      closeBtn.innerHTML = "&times;";
      closeBtn.setAttribute("aria-label", "Cerrar modal");
      closeBtn.addEventListener("click", () => this.abort());
      this.overlayEl.appendChild(closeBtn);
      this.overlayEl.addEventListener("click", (event) => {
        if (event.target === this.overlayEl) {
          this.abort();
        }
      });
      this.shadowRoot.appendChild(this.overlayEl);
      document.body.appendChild(this.hostEl);
    }
    this.iframe = document.createElement("iframe");
    this.iframe.className = "sso-frame";
    this.iframe.src = buildSsoFrameUrl(
      this.options.ssoOrigin,
      this.options.clientId,
      this.options.tenantId
    );
    this.iframe.setAttribute("title", "SSO Login");
    this.overlayEl.appendChild(this.iframe);
    this.debug("Iframe creado", this.iframe.src);
    this.overlayEl.classList.remove("sso-closing");
    this.overlayEl.style.display = "flex";
  }
  closeUI() {
    if (!this.overlayEl || this.overlayEl.style.display === "none") return;
    this.overlayEl.classList.add("sso-closing");
    setTimeout(() => {
      if (this.overlayEl) {
        this.overlayEl.style.display = "none";
        this.overlayEl.classList.remove("sso-closing");
      }
    }, 200);
  }
  getOverlayStyles() {
    return `
            .sso-overlay {
                position: fixed;
                inset: 0;
                display: none;
                justify-content: center;
                align-items: center;
                background: rgba(0, 0, 0, 0.6);
                z-index: 999999;
                backdrop-filter: blur(4px);
                -webkit-backdrop-filter: blur(4px);
                animation: fadeIn 0.2s ease;
            }
            .sso-frame {
                width: 100%;
                height: 100%;
                max-width: 400px;
                max-height: 600px;
                border: none;
                border-radius: 16px;
                background: var(--card-bg, #fff);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.3);
                animation: slideUp 0.3s ease;
            }
            @media (max-width: 480px), (max-height: 480px) {
                .sso-frame {
                    width: 100%;
                    height: 100%;
                    max-width: 100dvw;
                    max-height: 100dvh;
                    border-radius: 0;
                }
                           }
            .sso-close-btn {
                position: absolute;
                top: 12px;
                right: 12px;
                width: 32px;
                height: 32px;
                background: rgba(0, 0, 0, 0.4);
                color: white;
                border: none;
                border-radius: 50%;
                font-size: 24px;
                line-height: 1;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000000;
                transition: background 0.2s;
            }
            .sso-close-btn:hover {
                background: rgba(0, 0, 0, 0.8);
            }
            .sso-overlay.sso-closing {
                animation: fadeOut 0.2s ease forwards;
            }
            .sso-overlay.sso-closing .sso-frame {
                animation: slideDown 0.2s ease forwards;
            }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            @keyframes slideUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
            @keyframes fadeOut { from { opacity: 1; } to { opacity: 0; } }
            @keyframes slideDown { from { transform: translateY(0); opacity: 1; } to { transform: translateY(20px); opacity: 0; } }
        `;
  }
  // ─── Helpers ──────────────────────────────────────────────────────
  buildFallbackUrl(codeChallenge, state) {
    const url = new URL(this.options.ssoOrigin);
    url.searchParams.set("app_id", this.options.clientId);
    url.searchParams.set("redirect_uri", this.options.redirectUri || window.location.origin);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("client_id", this.options.clientId);
    if (this.options.tenantId) {
      url.searchParams.set("tenant_id", this.options.tenantId);
    }
    return url.toString();
  }
  debug(...args) {
    if (this.options.debug) {
      console.log("[BigsoAuth]", ...args);
    }
  }
};

// src/types.ts
var CONTEXTUAL_LAUNCH_PROTOCOL = "bigso-context-launch-v1";

// src/browser/contextualLaunch.ts
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var TRANSACTION_KEY = "bigso_context_launch_v1";
var TRANSACTION_TTL_MS = 5 * 60 * 1e3;
function normalizeReturnPath(value, fallback = "/") {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return fallback;
  try {
    const parsed = new URL(value, "https://launch.invalid");
    if (parsed.origin !== "https://launch.invalid") return fallback;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return fallback;
  }
}
function parseContextualLaunch(search, fallback = "/") {
  const params = new URLSearchParams(search);
  const tenantHint = params.get("tenant_hint") || void 0;
  return {
    tenantHint: tenantHint && UUID.test(tenantHint) ? tenantHint : void 0,
    returnPath: normalizeReturnPath(params.get("return_path"), fallback),
    correlationId: params.get("correlation_id") || generateRandomId()
  };
}
function buildContextualLaunchUrl(application, tenantId, returnPath, correlationId = generateRandomId()) {
  const base = application.launchProtocol === CONTEXTUAL_LAUNCH_PROTOCOL && application.launchUrl ? application.launchUrl : application.url;
  const url = new URL(base);
  if (application.launchProtocol === CONTEXTUAL_LAUNCH_PROTOCOL && application.launchUrl) {
    if (!UUID.test(tenantId)) throw new Error("tenantId must be a UUID");
    url.searchParams.set("tenant_hint", tenantId);
    url.searchParams.set("correlation_id", correlationId);
    if (returnPath) url.searchParams.set("return_path", normalizeReturnPath(returnPath));
  }
  return url.toString();
}
var ContextualLaunchAdapter = class {
  constructor(options) {
    this.options = options;
  }
  async launch(search = window.location.search) {
    const context = parseContextualLaunch(search, this.options.defaultReturnPath);
    if (context.tenantHint && this.options.isSessionReusable && await this.options.isSessionReusable(context.tenantHint)) {
      this.options.navigate(context.returnPath);
      return "reused";
    }
    if (!context.tenantHint) throw new Error("invalid_launch_context");
    if (!this.options.redirectUri) throw new Error("redirectUri is required for contextual launch");
    const state = generateRandomId();
    const nonce = generateRandomId();
    const verifier = generateVerifier(48);
    const challenge = await sha256Base64Url(verifier);
    const transaction = {
      state,
      nonce,
      verifier,
      returnPath: context.returnPath,
      createdAt: Date.now()
    };
    sessionStorage.setItem(TRANSACTION_KEY, JSON.stringify(transaction));
    const authorizeUrl = new URL(this.options.authorizationPath ?? "/auth/launch", this.options.ssoOrigin);
    authorizeUrl.searchParams.set("app_id", this.options.clientId);
    authorizeUrl.searchParams.set("tenant_id", context.tenantHint);
    authorizeUrl.searchParams.set("redirect_uri", this.options.redirectUri);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("nonce", nonce);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");
    authorizeUrl.searchParams.set("correlation_id", context.correlationId);
    window.location.assign(authorizeUrl.toString());
    return "redirected";
  }
  async complete(search = window.location.search) {
    const params = new URLSearchParams(search);
    const state = params.get("state");
    const signedPayload = params.get("payload");
    const raw = sessionStorage.getItem(TRANSACTION_KEY);
    sessionStorage.removeItem(TRANSACTION_KEY);
    if (!raw || !state || !signedPayload) throw new Error("invalid_launch_context");
    const transaction = JSON.parse(raw);
    if (transaction.state !== state || Date.now() - transaction.createdAt > TRANSACTION_TTL_MS) {
      throw new Error("authorization_expired");
    }
    history.replaceState({}, document.title, window.location.pathname);
    await this.options.onAuthenticated({
      code: "",
      state,
      nonce: transaction.nonce,
      codeVerifier: transaction.verifier,
      signed_payload: signedPayload
    }, transaction.returnPath);
  }
};

// src/browser/logout.ts
async function logout(options) {
  if (options.scope !== "application" && options.scope !== "global") {
    throw new Error("Unsupported logout scope");
  }
  const fetcher = options.fetch ?? globalThis.fetch;
  const endpoint = options.endpoint ?? "/api/auth/logout";
  await options.onTransitionStart?.();
  try {
    const response = await fetcher(endpoint, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope: options.scope })
    });
    if (!response.ok) throw new Error(`Logout failed (status: ${response.status})`);
    const result = await response.json();
    if (!result.success || result.scope !== options.scope) {
      throw new Error("Invalid logout response");
    }
    if (options.scope === "global") {
      if (!result.continueUrl || !result.state || !options.identityOrigin) {
        throw new Error("Global logout requires an Identity continuation");
      }
      const continuation = new URL(result.continueUrl);
      if (continuation.origin !== new URL(options.identityOrigin).origin) {
        throw new Error("Untrusted global logout continuation");
      }
      ;
      (options.storage ?? window.sessionStorage).setItem("bigso_logout_state_v1", result.state);
      (options.navigate ?? ((url) => window.location.assign(url)))(continuation.toString());
    }
    return result;
  } catch (cause) {
    const error = cause instanceof Error ? cause : new Error("Logout failed");
    await options.onTransitionError?.(error);
    throw error;
  }
}
function logoutApplication(options) {
  return logout({ ...options, scope: "application" });
}
function logoutGlobally(options) {
  return logout({ ...options, scope: "global" });
}
export {
  BigsoAuth,
  CONTEXTUAL_LAUNCH_PROTOCOL,
  ContextualLaunchAdapter,
  buildContextualLaunchUrl,
  logout,
  logoutApplication,
  logoutGlobally,
  normalizeReturnPath,
  parseContextualLaunch
};
