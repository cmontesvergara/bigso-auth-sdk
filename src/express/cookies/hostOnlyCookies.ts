import type { CookieConfigWithOptionalSameSite } from '../routes/createSsoAuthRouter';
import type { Response } from 'express';

/**
 * Canonical host-only cookie profile for BIGSO application sessions.
 *
 * Requirements:
 * - Name starts with `__Host-` so the browser enforces Secure, HttpOnly, Path=/ and no Domain.
 * - Secure is true (host-only `__Host-*` cookies are rejected over plain HTTP by modern browsers).
 * - HttpOnly so JavaScript cannot read the session handle.
 * - Path=/ so the cookie is sent to every route of the exact host.
 * - No Domain attribute so the cookie is bound to the exact middleware hostname.
 * - SameSite defaults to 'strict' and is configurable only for topologies that require lax.
 *
 * The SDK still accepts a consumer-provided `CookieConfig` for the transition window, but
 * production deployments SHOULD set `hostOnly: true` to adopt the `__Host-Http-*` profile.
 */
export interface HostOnlyCookieConfig extends CookieConfigWithOptionalSameSite {
    /** When true, emit the canonical `__Host-Http-bigso-session-<app>` cookie. */
    hostOnly: true;
    /**
     * Human-readable application slug used in the cookie name.
     * Must be kebab-case and unique per application.
     */
    appSlug: string;
    /** Optional set of legacy cookie names to clear during migration. */
    legacyCookies?: LegacyCookieDefinition[];
    /** Explicit SameSite value. Defaults to 'strict'. */
    sameSite?: 'strict' | 'lax' | 'none';
}

export interface LegacyCookieDefinition {
    /** Legacy cookie name to expire. */
    name: string;
    /** Domain that was used to set the legacy cookie. Omit for host-only variants. */
    domain?: string;
    /** Path that was used to set the legacy cookie. Defaults to '/'. */
    path?: string;
}

export type EffectiveCookieConfig = CookieConfigWithOptionalSameSite | HostOnlyCookieConfig;

export function isHostOnlyConfig(config: EffectiveCookieConfig | undefined): config is HostOnlyCookieConfig {
    return !!config && (config as HostOnlyCookieConfig).hostOnly === true && !!(config as HostOnlyCookieConfig).appSlug;
}

/**
 * Builds the canonical host-only session cookie name.
 *
 * The `__Host-` prefix causes browsers to reject the cookie unless it is set with
 * Secure, HttpOnly, Path=/ and without a Domain attribute. We append a BIGSO-specific
 * namespace to avoid collisions with other frameworks.
 */
export function hostOnlySessionName(appSlug: string): string {
    return `__Host-Http-bigso-session-${appSlug}`;
}

/**
 * Derives the cookie options for the host-only profile.
 * `secure` is forced to true: a `__Host-*` cookie sent over HTTP would be rejected anyway.
 */
export function hostOnlyCookieOptions(maxAge: number, sameSite: 'strict' | 'lax' | 'none' = 'strict') {
    return {
        httpOnly: true,
        secure: true,
        sameSite,
        path: '/',
        maxAge,
    } as const;
}

/**
 * Clears both known legacy cookie variants: parent-domain and host-only.
 *
 * During the migration window a single browser may hold cookies emitted under the old
 * name with the old domain AND the same name without domain (e.g. after a local change
 * or a test). We expire every known variant explicitly so the browser never has multiple
 * active cookies with the same name and ambiguous scope.
 */
export function clearLegacyCookies(
    res: Response,
    legacyCookies: LegacyCookieDefinition[],
): void {
    for (const { name, domain, path = '/' } of legacyCookies) {
        // Clear parent-domain variant if a domain was configured historically.
        if (domain) {
            res.clearCookie(name, { domain, path });
        }
        // Always clear host-only variant (no domain) for the same name.
        res.clearCookie(name, { path });
    }
}

/**
 * Builds a Set-Cookie options object compatible with the configured profile.
 *
 * For host-only configs it returns the canonical `__Host-*` options and ignores
 * any `domain`/`sessionPath` provided in the legacy CookieConfig fields.
 * For legacy configs it preserves the supplied domain/path for backward compatibility.
 */
export function buildSessionCookieOptions(
    config: EffectiveCookieConfig,
): { name: string; options: import('express').CookieOptions } {
    if (isHostOnlyConfig(config)) {
        return {
            name: hostOnlySessionName(config.appSlug),
            options: hostOnlyCookieOptions(config.maxAge, config.sameSite ?? 'strict'),
        };
    }
    return {
        name: config.sessionName,
        options: {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: config.sameSite,
            path: config.sessionPath,
            maxAge: config.maxAge,
            domain: config.domain,
        },
    };
}

/**
 * Returns all cookie names that could have been used for an application session.
 * Useful for BFF middleware that needs to look up either the new host-only cookie or
 * a known legacy name during the migration window.
 */
export function resolveSessionCookieNames(config: EffectiveCookieConfig): string[] {
    if (isHostOnlyConfig(config)) {
        const names = new Set<string>([hostOnlySessionName(config.appSlug)]);
        for (const legacy of config.legacyCookies ?? []) {
            names.add(legacy.name);
        }
        return [...names];
    }
    return [config.sessionName];
}
