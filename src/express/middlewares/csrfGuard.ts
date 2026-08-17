import { createHash, randomBytes } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

const CSRF_HEADER = 'x-csrf-token';

export interface CsrfMiddlewareOptions {
    /**
     * Function that extracts the CSRF token bound to the current application session.
     * The session handle should be read from the HttpOnly host-only session cookie.
     */
    getSessionCsrfToken: (req: Request) => string | undefined;
    /**
     * Approved origins for cookie-authenticated mutations. The request Origin header
     * must match exactly one entry (case-insensitive). In production this list is small.
     */
    allowedOrigins: string[];
    /**
     * When true, enforce Sec-Fetch-Site metadata as an additional signal.
     * Recommended for modern same-site deployments.
     */
    requireSameSiteFetch?: boolean;
    /**
     * Optional extra predicate for routes that should skip CSRF checks.
     * Safe methods (GET, HEAD, OPTIONS, TRACE) are always skipped.
     */
    skipIf?: (req: Request) => boolean;
}

function normalizeOrigin(origin: string | undefined): string | undefined {
    if (!origin) return undefined;
    try {
        return new URL(origin).origin.toLowerCase();
    } catch {
        return origin.toLowerCase();
    }
}

function approvedOrigin(origin: string | undefined, allowed: string[]): boolean {
    const normalized = normalizeOrigin(origin);
    if (!normalized) return false;
    const allowedSet = new Set(allowed.map((o) => normalizeOrigin(o)).filter((o): o is string => !!o));
    return allowedSet.has(normalized);
}

/**
 * Generates a session-bound CSRF token. The value is deterministic for a given session
 * so that multiple tabs or reloads share the same token, but it is not guessable from
 * outside because it depends on a server-only session secret and the opaque handle.
 */
export function generateCsrfToken(sessionHandle: string, sessionSecret: string): string {
    return createHash('sha256')
        .update(`${sessionSecret}:${sessionHandle}:${sessionSecret}`)
        .digest('base64url')
        .slice(0, 32);
}

/**
 * Generates a fresh random secret used by the BFF to sign/prove session-bound CSRF tokens.
 * This secret lives in server memory (or a distributed cache in multi-instance deployments)
 * and must never reach the browser.
 */
export function generateCsrfSecret(): string {
    return randomBytes(32).toString('base64url');
}

/**
 * Express middleware that enforces Origin + CSRF token validation on state-changing
 * cookie-authenticated requests.
 *
 * Fail-closed behavior:
 * - Missing or unapproved Origin → 403 csrf_or_origin_mismatch
 * - Missing or mismatched CSRF token → 403 csrf_or_origin_mismatch
 * - Unsafe Sec-Fetch-Site (when required) → 403 csrf_or_origin_mismatch
 *
 * GET/HEAD/OPTIONS/TRACE are always allowed because they must not mutate state.
 */
export interface CsrfValidationResult {
    ok: true;
}

export interface CsrfValidationFailure {
    ok: false;
    reason: 'method_safe' | 'skipped' | 'origin_mismatch' | 'sec_fetch_site_mismatch' | 'missing_header' | 'token_mismatch';
}

export function validateCsrf(req: Request, options: CsrfMiddlewareOptions): CsrfValidationResult | CsrfValidationFailure {
    const method = req.method?.toUpperCase() ?? '';
    if (['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
        return { ok: true };
    }

    if (options.skipIf?.(req)) {
        return { ok: true };
    }

    const origin = req.headers.origin as string | undefined;
    if (!approvedOrigin(origin, options.allowedOrigins)) {
        return { ok: false, reason: 'origin_mismatch' };
    }

    if (options.requireSameSiteFetch) {
        const secFetchSite = req.headers['sec-fetch-site'] as string | undefined;
        // Accept same-origin and same-site requests. BFF deployments where the
        // frontend and middleware share an eTLD+1 but live on different subdomains
        // (e.g. www.ordamy.com -> new-middleware.ordamy.com) send same-site, not
        // same-origin. Reject only explicit cross-site navigations.
        if (secFetchSite) {
            const site = secFetchSite.toLowerCase();
            if (site !== 'same-origin' && site !== 'same-site') {
                return { ok: false, reason: 'sec_fetch_site_mismatch' };
            }
        }
    }

    const headerToken = (req.headers[CSRF_HEADER] as string | undefined)?.trim();
    if (!headerToken) {
        return { ok: false, reason: 'missing_header' };
    }

    const sessionToken = options.getSessionCsrfToken(req);
    if (!sessionToken || headerToken !== sessionToken) {
        return { ok: false, reason: 'token_mismatch' };
    }

    return { ok: true };
}

export function csrfGuardMiddleware(options: CsrfMiddlewareOptions) {
    const allowedOrigins = options.allowedOrigins.map((o) => o.trim()).filter(Boolean);

    return (req: Request, res: Response, next: NextFunction) => {
        const result = validateCsrf(req, { ...options, allowedOrigins });
        if (result.ok) {
            next();
            return;
        }
        res.status(403).json({ error: 'csrf_or_origin_mismatch' });
    };
}
