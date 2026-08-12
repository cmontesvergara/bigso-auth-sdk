import { beforeEach, describe, expect, it, vi } from 'vitest'
import { buildTopLevelAuthUrl, EMBEDDED_AUTH_TRANSACTION_KEY } from './topLevelAuth'

describe('embedded auth top-level continuation', () => {
    beforeEach(() => {
        vi.stubGlobal('window', { location: { origin: 'https://app.example', pathname: '/auth/callback' } })
    })

    it('builds a state and PKCE-bound identity launch without credentials', () => {
        const url = new URL(buildTopLevelAuthUrl({
            clientId: 'app-id', ssoOrigin: 'https://auth.bigso.cloud', jwksUrl: 'https://api.bigso.cloud/jwks',
            redirectUri: 'https://app.example/auth/callback', tenantId: 'tenant-id',
        }, 'challenge', 'state', 'nonce'))
        expect(url.pathname).toBe('/auth/launch')
        expect(url.searchParams.get('code_challenge_method')).toBe('S256')
        expect(url.searchParams.get('state')).toBe('state')
        expect(url.searchParams.get('nonce')).toBe('nonce')
        expect(url.toString()).not.toContain('verifier')
    })

    it('uses the current route as the default registered callback', () => {
        const url = new URL(buildTopLevelAuthUrl({
            clientId: 'app-id', ssoOrigin: 'https://auth.bigso.cloud', jwksUrl: 'https://api.bigso.cloud/jwks',
        }, 'challenge', 'state', 'nonce'))
        expect(url.searchParams.get('redirect_uri')).toBe('https://app.example/auth/callback')
        expect(EMBEDDED_AUTH_TRANSACTION_KEY).toBe('sso_ctx')
    })
})
