/**
 * Security regression tests for the host-only cookie profile and CSRF guard.
 *
 * These tests verify Phase 4 of harden-browser-session-boundaries:
 *   - cookie tossing and sibling-subdomain rejection
 *   - cross-site form / Origin mismatch rejection
 *   - missing or mismatched CSRF token rejection
 *   - double-submit CSRF rejection
 *   - safe methods are always allowed
 *
 * The router is exercised with hostOnlyCookies: true to ensure fail-closed
 * behavior without legacy fallback.
 */
import express from 'express';
import http from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSsoAuthRouter } from './routes/createSsoAuthRouter';
import { csrfGuardMiddleware, generateCsrfToken } from './middlewares/csrfGuard';

const TEST_ORIGIN = 'https://app.bigso.test';
const SIBLING_ORIGIN = 'https://evil.bigso.test';

const hostOnlyCookieConfig = {
    sessionName: '__Host-Http-bigso-session-testapp',
    refreshName: 'bigapp-refresh-testapp',
    permissionName: 'bigapp-permissions-testapp',
    domain: '',
    sessionPath: '/',
    refreshPath: '/',
    permissionPath: '/',
    sameSite: 'lax' as const,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    legacyCookies: [
        { name: 'bigapp-session-testapp', domain: '.bigso.test', path: '/' },
        { name: 'bigapp-session-testapp', path: '/' },
    ],
};

function createMockClient(extra: any = {}) {
    return {
        getClientOptions: () => ({ appId: 'testapp' }),
        session: vi.fn().mockResolvedValue({
            success: true,
            tokens: { accessToken: 'mock-jwt' },
            user: { id: 'user-a', email: 'user@bigso.test', firstName: 'A', lastName: 'User' },
            currentTenant: { id: 'tenant-a', name: 'Tenant', slug: 'tenant', role: 'admin', permissions: [] },
        }),
        ...extra,
    };
}

async function serveAuthRouter(client: any) {
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { (req as any).cookies = { [hostOnlyCookieConfig.sessionName]: 'session-a' }; next(); });
    app.use('/auth', createSsoAuthRouter({
        ssoClient: client,
        frontendUrl: TEST_ORIGIN,
        cookieConfig: hostOnlyCookieConfig,
        hostOnlyCookies: true,
        appSlug: 'testapp',
        csrfSecret: 'static-csrf-secret-for-tests',
    }));
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Test server did not bind');
    return { server, baseUrl: `http://127.0.0.1:${address.port}/auth` };
}

function makeCsrfHeader(sessionHandle: string) {
    return generateCsrfToken(sessionHandle, 'static-csrf-secret-for-tests');
}

describe('host-only cookie profile', () => {
    const servers: any[] = [];
    afterEach(async () => {
        await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    });

    it('emits the __Host- cookie without a Domain attribute on exchange', async () => {
        const client = createMockClient({
            verifySignedPayload: vi.fn().mockResolvedValue({ code: 'code-a', code_verifier: 'verifier-a' }),
            exchangeCode: vi.fn().mockResolvedValue({
                success: true,
                sessionId: 'session-a',
                tokens: { jti: 'session-a', accessToken: 'access-a', refreshToken: 'refresh-a', expiresIn: 900 },
                user: { id: 'user-a', email: 'user@bigso.test', firstName: 'A', lastName: 'User' },
                currentTenant: { id: 'tenant-a', name: 'Tenant', slug: 'tenant', role: 'admin', permissions: [] },
                relatedTenants: [],
                activeApplications: [],
            }),
        });
        const running = await serveAuthRouter(client);
        servers.push(running.server);

        const response = await fetch(`${running.baseUrl}/exchange`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: 'signed-payload' }),
        });
        const setCookie = response.headers.getSetCookie();
        const sessionCookie = setCookie.find((c) => c.startsWith('__Host-Http-bigso-session-testapp='));

        expect(response.status).toBe(200);
        expect(sessionCookie).toBeDefined();
        expect(sessionCookie).toContain('Secure');
        expect(sessionCookie).toContain('HttpOnly');
        expect(sessionCookie).toContain('Path=/');
        expect(sessionCookie).not.toContain('Domain=');
        expect(sessionCookie).toContain('SameSite=Lax');
    });

    it('expires legacy cookies on exchange', async () => {
        const client = createMockClient({
            verifySignedPayload: vi.fn().mockResolvedValue({ code: 'code-a', code_verifier: 'verifier-a' }),
            exchangeCode: vi.fn().mockResolvedValue({
                success: true,
                sessionId: 'session-a',
                tokens: { jti: 'session-a', accessToken: 'access-a', refreshToken: 'refresh-a', expiresIn: 900 },
                user: { id: 'user-a', email: 'user@bigso.test', firstName: 'A', lastName: 'User' },
                currentTenant: { id: 'tenant-a', name: 'Tenant', slug: 'tenant', role: 'admin', permissions: [] },
                relatedTenants: [],
                activeApplications: [],
            }),
        });
        const running = await serveAuthRouter(client);
        servers.push(running.server);

        const response = await fetch(`${running.baseUrl}/exchange`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: 'signed-payload' }),
        });
        const setCookie = response.headers.getSetCookie();
        const legacyCleared = setCookie.filter((c) => c.includes('bigapp-session-testapp') && c.includes('Expires=Thu, 01 Jan 1970'));

        expect(legacyCleared.length).toBeGreaterThanOrEqual(2);
    });

    it('projects a csrfToken in public responses', async () => {
        const client = createMockClient({
            verifySignedPayload: vi.fn().mockResolvedValue({ code: 'code-a', code_verifier: 'verifier-a' }),
            exchangeCode: vi.fn().mockResolvedValue({
                success: true,
                sessionId: 'session-a',
                tokens: { jti: 'session-a', accessToken: 'access-a', refreshToken: 'refresh-a', expiresIn: 900 },
                user: { id: 'user-a', email: 'user@bigso.test', firstName: 'A', lastName: 'User' },
                currentTenant: { id: 'tenant-a', name: 'Tenant', slug: 'tenant', role: 'admin', permissions: [] },
                relatedTenants: [],
                activeApplications: [],
            }),
        });
        const running = await serveAuthRouter(client);
        servers.push(running.server);

        const response = await fetch(`${running.baseUrl}/exchange`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: 'signed-payload' }),
        });
        const body = await response.json();

        expect(body.csrfToken).toBe(makeCsrfHeader('session-a'));
    });

    it('rotates the host-only session cookie on tenant switch', async () => {
        const client = createMockClient({
            authorizeTenant: vi.fn().mockResolvedValue({ code: 'code-b' }),
            exchangeCode: vi.fn().mockResolvedValue({
                success: true,
                sessionId: 'session-b',
                tokens: { jti: 'session-b', accessToken: 'access-b', refreshToken: 'refresh-b' },
                user: { id: 'user-a', email: 'user@bigso.test' },
                currentTenant: { id: 'tenant-b', permissions: [] },
            }),
        });
        const running = await serveAuthRouter(client);
        servers.push(running.server);

        const response = await fetch(`${running.baseUrl}/tenant-context`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Origin: TEST_ORIGIN,
                'X-Csrf-Token': makeCsrfHeader('session-a'),
            },
            body: JSON.stringify({ tenantId: 'tenant-b' }),
        });
        const setCookie = response.headers.getSetCookie();
        const sessionCookie = setCookie.find((c) => c.startsWith('__Host-Http-bigso-session-testapp=session-b'));

        expect(response.status).toBe(200);
        expect(sessionCookie).toBeDefined();
        expect(sessionCookie).not.toContain('Domain=');
        const body = await response.json();
        expect(body.csrfToken).toBe(makeCsrfHeader('session-b'));
    });
});

describe('CSRF guard fail-closed behavior', () => {
    const servers: any[] = [];
    afterEach(async () => {
        await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    });

    function makeApp() {
        const app = express();
        app.use(express.json());
        app.use((req, _res, next) => {
            const raw = req.headers.cookie as string | undefined;
            (req as any).cookies = raw
                ? Object.fromEntries(raw.split(';').map((c) => c.trim().split('=').map((p) => decodeURIComponent(p))))
                : {};
            next();
        });
        const guard = csrfGuardMiddleware({
            getSessionCsrfToken: (req) => {
                const handle = req.cookies?.[hostOnlyCookieConfig.sessionName];
                return handle ? generateCsrfToken(handle, 'static-csrf-secret-for-tests') : undefined;
            },
            allowedOrigins: [TEST_ORIGIN],
            requireSameSiteFetch: false,
        });
        app.post('/mutate', guard, (_req, res) => res.json({ ok: true }));
        app.get('/safe', guard, (_req, res) => res.json({ ok: true }));
        return app;
    }

    async function serveGuard() {
        const app = makeApp();
        const server = app.listen(0);
        await new Promise<void>((resolve) => server.once('listening', resolve));
        const address = server.address();
        if (!address || typeof address === 'string') throw new Error('Test server did not bind');
        return { server, url: `http://127.0.0.1:${address.port}` };
    }

    it('allows safe methods without CSRF token', async () => {
        const running = await serveGuard();
        servers.push(running.server);
        const response = await fetch(`${running.url}/safe`);
        expect(response.status).toBe(200);
    });

    it('rejects mutating request from sibling subdomain', async () => {
        const running = await serveGuard();
        servers.push(running.server);
        const response = await fetch(`${running.url}/mutate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Origin: SIBLING_ORIGIN },
            body: JSON.stringify({}),
        });
        expect(response.status).toBe(403);
        expect(await response.json()).toEqual({ error: 'csrf_or_origin_mismatch' });
    });

    it('rejects cross-site request without Origin header', async () => {
        const running = await serveGuard();
        servers.push(running.server);
        const response = await fetch(`${running.url}/mutate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        expect(response.status).toBe(403);
    });

    it('rejects mutating request with valid Origin but missing CSRF token', async () => {
        const running = await serveGuard();
        servers.push(running.server);
        const response = await fetch(`${running.url}/mutate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
            body: JSON.stringify({}),
        });
        expect(response.status).toBe(403);
    });

    it('rejects mutating request with mismatched CSRF token (double submit)', async () => {
        const running = await serveGuard();
        servers.push(running.server);
        const agent = new http.Agent({ keepAlive: false });
        const response = await fetch(`${running.url}/mutate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Origin: TEST_ORIGIN,
                'X-Csrf-Token': 'attacker-token',
                Cookie: `${hostOnlyCookieConfig.sessionName}=session-a`,
            },
            body: JSON.stringify({}),
            agent,
        });
        expect(response.status).toBe(403);
    });

    it('allows mutating request with valid Origin and matching CSRF token', async () => {
        const running = await serveGuard();
        servers.push(running.server);
        const response = await fetch(`${running.url}/mutate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Origin: TEST_ORIGIN,
                'X-Csrf-Token': makeCsrfHeader('session-a'),
                Cookie: `${hostOnlyCookieConfig.sessionName}=session-a`,
            },
            body: JSON.stringify({}),
        });
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ ok: true });
    });

    it('rejects request with Sec-Fetch-Site cross-site when enforcement is enabled', async () => {
        const app = express();
        app.use(express.json());
        app.use((req, _res, next) => {
            const raw = req.headers.cookie as string | undefined;
            (req as any).cookies = raw
                ? Object.fromEntries(raw.split(';').map((c) => c.trim().split('=').map((p) => decodeURIComponent(p))))
                : {};
            next();
        });
        const guard = csrfGuardMiddleware({
            getSessionCsrfToken: (req) => {
                const handle = req.cookies?.[hostOnlyCookieConfig.sessionName];
                return handle ? generateCsrfToken(handle, 'static-csrf-secret-for-tests') : undefined;
            },
            allowedOrigins: [TEST_ORIGIN],
            requireSameSiteFetch: true,
        });
        app.post('/mutate', guard, (_req, res) => res.json({ ok: true }));
        const server = app.listen(0);
        await new Promise<void>((resolve) => server.once('listening', resolve));
        const address = server.address();
        if (!address || typeof address === 'string') throw new Error('Test server did not bind');
        servers.push(server);

        const response = await fetch(`http://127.0.0.1:${address.port}/mutate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Origin: TEST_ORIGIN,
                'Sec-Fetch-Site': 'cross-site',
                'X-Csrf-Token': makeCsrfHeader('session-a'),
                Cookie: `${hostOnlyCookieConfig.sessionName}=session-a`,
            },
            body: JSON.stringify({}),
        });
        expect(response.status).toBe(403);
    });
});
