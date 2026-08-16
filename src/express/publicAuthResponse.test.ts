import { describe, expect, it } from 'vitest';
import { projectPublicAuthResponse } from './publicAuthResponse';

const forbiddenKey = /^(accessToken|refreshToken|token|tokens|tokenHash|jti|sid|sessionId|nuid|roleId)$/i;
const jwtPattern = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

function assertNoCredential(value: unknown, path = '$'): void {
    if (typeof value === 'string') {
        expect(value, `JWT leaked at ${path}`).not.toMatch(jwtPattern);
        return;
    }
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoCredential(item, `${path}[${index}]`));
        return;
    }
    if (!value || typeof value !== 'object') return;
    for (const [key, nested] of Object.entries(value)) {
        expect(key, `credential key leaked at ${path}.${key}`).not.toMatch(forbiddenKey);
        assertNoCredential(nested, `${path}.${key}`);
    }
}

describe('projectPublicAuthResponse', () => {
    it('allowlists presentation context and removes credentials at every nesting level', () => {
        const result = projectPublicAuthResponse({
            success: true,
            accessToken: 'eyJheader.payload.signature',
            refreshToken: 'eyJrefresh.payload.signature',
            tokens: {
                accessToken: 'eyJnested.payload.signature',
                refreshToken: 'eyJnestedrefresh.payload.signature',
                jti: 'token-id',
                expiresIn: 900,
            },
            user: {
                id: 'user-a', email: 'user@bigso.test', firstName: 'Ada', lastName: 'Lovelace',
                systemRole: 'super_admin', passwordHash: 'hash', nuid: 'secret-id',
            },
            currentTenant: {
                id: 'tenant-a', name: 'BIGSO', slug: 'bigso', role: 'admin', roleId: 'role-a',
                permissions: [{ resource: 'orders', action: 'read', internalId: 'permission-a' }],
            },
            relatedTenants: [{
                id: 'tenant-b', name: 'Labs', slug: 'labs', role: 'member',
                permissions: [{ resource: 'reports', action: 'read' }],
                tokens: { refreshToken: 'eyJbad.payload.signature' },
            }],
            activeApplications: [{ appId: 'app-a', name: 'Ordamy', logoUrl: null, secret: 'hidden' }],
            internal: { tokenHash: 'hidden' },
        });

        expect(result).toEqual({
            success: true,
            expiresIn: 900,
            user: { userId: 'user-a', email: 'user@bigso.test', firstName: 'Ada', lastName: 'Lovelace' },
            currentTenant: {
                id: 'tenant-a', name: 'BIGSO', slug: 'bigso', role: 'admin',
                permissions: [{ resource: 'orders', action: 'read' }],
            },
            relatedTenants: [{
                id: 'tenant-b', name: 'Labs', slug: 'labs', role: 'member',
                permissions: [{ resource: 'reports', action: 'read' }],
            }],
            activeApplications: [{ appId: 'app-a', name: 'Ordamy', logoUrl: null }],
        });
        assertNoCredential(result);
    });

    it('returns a stable minimal response for malformed upstream data', () => {
        expect(projectPublicAuthResponse({ success: true, tokens: null, user: 'invalid' }))
            .toEqual({ success: true });
    });
});
