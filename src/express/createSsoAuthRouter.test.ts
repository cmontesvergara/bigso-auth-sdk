import express from 'express';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSsoAuthRouter, type CookieConfig } from './routes/createSsoAuthRouter';

const cookieConfig: CookieConfig = {
    sessionName: 'app-session', refreshName: 'app-refresh', permissionName: 'app-permissions',
    domain: '', sessionPath: '/', refreshPath: '/', permissionPath: '/', sameSite: 'lax', maxAge: 60_000,
};

async function serve(client: any) {
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { (req as any).cookies = { 'app-session': 'session-a' }; next(); });
    app.use('/auth', createSsoAuthRouter({ ssoClient: client, frontendUrl: 'https://app.bigso.test', cookieConfig }));
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Test server did not bind');
    return { server, url: `http://127.0.0.1:${address.port}/auth/tenant-context` };
}

async function serveRefresh(client: any) {
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
        (req as any).cookies = { 'app-session': 'session-a', 'app-refresh': 'refresh-a' };
        next();
    });
    app.use('/auth', createSsoAuthRouter({
        ssoClient: client,
        frontendUrl: 'https://app.bigso.test',
        cookieConfig,
    }));
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Test server did not bind');
    return { server, url: `http://127.0.0.1:${address.port}/auth/refresh` };
}

async function serveAuthRoute(client: any, route: 'exchange' | 'session') {
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { (req as any).cookies = { 'app-session': 'session-a' }; next(); });
    app.use('/auth', createSsoAuthRouter({
        ssoClient: client,
        frontendUrl: 'https://app.bigso.test',
        cookieConfig,
    }));
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Test server did not bind');
    return { server, url: `http://127.0.0.1:${address.port}/auth/${route}` };
}

function expectNoPrivateSessionFields(body: unknown): void {
    const serialized = JSON.stringify(body);
    for (const forbidden of ['accessToken', 'refreshToken', 'tokens', 'jti', 'sessionId', 'nuid', 'roleId']) {
        expect(serialized).not.toContain(`"${forbidden}"`);
    }
}

describe('public authentication projections', () => {
    const servers: any[] = [];
    afterEach(async () => {
        await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    });

    it('sanitizes exchange responses recursively', async () => {
        const client = {
            verifySignedPayload: vi.fn().mockResolvedValue({ code: 'code-a', code_verifier: 'verifier-a' }),
            exchangeCode: vi.fn().mockResolvedValue({
                success: true,
                tokens: { jti: 'session-a', accessToken: 'access-a', refreshToken: 'refresh-a', expiresIn: 900 },
                user: { id: 'user-a', email: 'user@bigso.test', firstName: 'A', lastName: 'User', nuid: 'private' },
                currentTenant: { id: 'tenant-a', name: 'Tenant', slug: 'tenant', role: 'admin', permissions: [] },
                relatedTenants: [],
                activeApplications: [],
            }),
        };
        const running = await serveAuthRoute(client, 'exchange');
        servers.push(running.server);

        const response = await fetch(running.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: 'signed-payload' }),
        });
        const body = await response.json();

        expect(response.status).toBe(200);
        expect(body.expiresIn).toBe(900);
        expectNoPrivateSessionFields(body);
    });

    it('sanitizes session responses recursively', async () => {
        const client = {
            getClientOptions: () => ({ appId: 'app-a' }),
            session: vi.fn().mockResolvedValue({
                tokens: { jti: 'session-a', accessToken: 'access-a', refreshToken: 'refresh-a' },
                user: { id: 'user-a', email: 'user@bigso.test', firstName: 'A', lastName: 'User' },
                currentTenant: { id: 'tenant-a', name: 'Tenant', slug: 'tenant', role: 'admin', permissions: [] },
            }),
        };
        const running = await serveAuthRoute(client, 'session');
        servers.push(running.server);

        const response = await fetch(running.url);
        const body = await response.json();

        expect(response.status).toBe(200);
        expectNoPrivateSessionFields(body);
    });
});

describe('tenant session replacement route', () => {
    const servers: any[] = [];
    afterEach(async () => {
        await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    });

    it('uses the HttpOnly application session when the browser sends no bearer token', async () => {
        const client = {
            getClientOptions: () => ({ appId: 'app-a' }),
            session: vi.fn().mockResolvedValue({ tokens: { accessToken: 'access-a' } }),
            authorizeTenant: vi.fn().mockResolvedValue({ code: 'code-b' }),
            exchangeCode: vi.fn().mockResolvedValue({
                success: true,
                tokens: { jti: 'session-b', accessToken: 'access-b', refreshToken: 'refresh-b' },
                currentTenant: { id: 'tenant-b', permissions: [{ resource: 'orders', action: 'read' }] },
            }),
        };
        const running = await serve(client);
        servers.push(running.server);
        const response = await fetch(running.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tenantId: 'tenant-b' }) });

        expect(response.status).toBe(200);
        expect(client.session).toHaveBeenCalledWith('session-a', 'app-a');
        expect(client.authorizeTenant).toHaveBeenCalledWith(expect.objectContaining({ accessToken: 'access-a', tenantId: 'tenant-b' }));
        expect(response.headers.getSetCookie()).toHaveLength(3);
        expect(await response.json()).not.toHaveProperty('tokens');
    });

    it('clears every application cookie when replacement fails after authorization', async () => {
        const client = {
            getClientOptions: () => ({ appId: 'app-a' }),
            session: vi.fn().mockResolvedValue({ tokens: { accessToken: 'access-a' } }),
            authorizeTenant: vi.fn().mockResolvedValue({ code: 'code-b' }),
            exchangeCode: vi.fn().mockRejectedValue(new Error('exchange failed')),
        };
        const running = await serve(client);
        servers.push(running.server);
        const response = await fetch(running.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tenantId: 'tenant-b' }) });

        expect(response.status).toBe(401);
        expect(response.headers.getSetCookie()).toHaveLength(3);
        expect(await response.json()).toEqual({ error: 'tenant_switch_failed' });
    });
});

describe('refresh route', () => {
    const servers: any[] = [];
    afterEach(async () => {
        await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    });

    it('rotates the app-session cookie and preserves tenant permissions', async () => {
        const client = {
            refreshTokens: vi.fn().mockResolvedValue({
                success: true,
                tokens: {
                    jti: 'session-b',
                    accessToken: 'access-b',
                    refreshToken: 'refresh-b',
                    expiresIn: 900,
                },
                currentTenant: {
                    id: 'tenant-a',
                    permissions: [{ resource: 'orders', action: 'read' }],
                },
                relatedTenants: [],
            }),
        };
        const running = await serveRefresh(client);
        servers.push(running.server);

        const response = await fetch(running.url, {
            method: 'POST',
            headers: { 'x-tenant-id': 'tenant-a' },
        });

        expect(response.status).toBe(200);
        const cookies = response.headers.getSetCookie();
        expect(cookies.some((cookie) => cookie.startsWith('app-session=session-b'))).toBe(true);
        expect(cookies.some((cookie) => cookie.startsWith('app-refresh=refresh-b'))).toBe(true);
        expect(cookies.some((cookie) => cookie.startsWith('app-permissions=orders%3Aread'))).toBe(true);
        const body = await response.json();
        expect(body.currentTenant.permissions).toEqual([{ resource: 'orders', action: 'read' }]);
        expect(body).not.toHaveProperty('tokens');
    });
});
