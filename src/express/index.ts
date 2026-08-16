export { ssoAuthMiddleware } from './middlewares/ssoAuth';
export type { SsoAuthMiddlewareOptions } from './middlewares/ssoAuth';

export {
    csrfGuardMiddleware,
    generateCsrfSecret,
    generateCsrfToken,
    validateCsrf,
} from './middlewares/csrfGuard';
export type {
    CsrfMiddlewareOptions,
    CsrfValidationFailure,
    CsrfValidationResult,
} from './middlewares/csrfGuard';

export { ssoSyncGuardMiddleware } from './middlewares/ssoSyncGuard';
export type { SsoSyncGuardOptions } from './middlewares/ssoSyncGuard';

export { createSsoAuthRouter } from './routes/createSsoAuthRouter';
export type { CreateSsoAuthRouterOptions, CookieConfig } from './routes/createSsoAuthRouter';
export { projectPublicAuthResponse } from './publicAuthResponse';
export type { PublicAuthResponse } from './publicAuthResponse';

export { createSsoSyncRouter } from './routes/createSsoSyncRouter';
export type { SsoSyncRouterOptions } from './routes/createSsoSyncRouter';

export { createContextualLaunchRouter } from './routes/createContextualLaunchRouter';
export type { ContextualLaunchRouterOptions } from './routes/createContextualLaunchRouter';

export {
    buildSessionCookieOptions,
    clearLegacyCookies,
    hostOnlyCookieOptions,
    hostOnlySessionName,
    isHostOnlyConfig,
    resolveSessionCookieNames,
} from './cookies/hostOnlyCookies';
export type { EffectiveCookieConfig, HostOnlyCookieConfig, LegacyCookieDefinition } from './cookies/hostOnlyCookies';

