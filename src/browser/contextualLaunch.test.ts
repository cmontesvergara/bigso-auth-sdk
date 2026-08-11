import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ContextualLaunchAdapter, buildContextualLaunchUrl, normalizeReturnPath, parseContextualLaunch } from './contextualLaunch'

const tenantId = '6615ba1e-73ee-4c6c-a689-2a8359253988'

describe('contextual app launch v1', () => {
    const storage = new Map<string, string>()

    beforeEach(() => {
        storage.clear()
        vi.stubGlobal('sessionStorage', {
            getItem: (key: string) => storage.get(key) ?? null,
            setItem: (key: string, value: string) => storage.set(key, value),
            removeItem: (key: string) => storage.delete(key),
        })
        vi.stubGlobal('window', {
            location: { search: '', pathname: '/launch', assign: vi.fn() },
        })
        vi.stubGlobal('history', { replaceState: vi.fn() })
        vi.stubGlobal('document', { title: 'Launch' })
    })
    it.each(['https://evil.example', '//evil.example/path', 'javascript:alert(1)', 'orders/42', '/\\evil'])('rejects unsafe return path %s', (path) => {
        expect(normalizeReturnPath(path, '/home')).toBe('/home')
    })

    it('parses a valid tenant hint and local return path', () => {
        expect(parseContextualLaunch(`?tenant_hint=${tenantId}&return_path=%2Forders%2F42`)).toMatchObject({
            tenantHint: tenantId,
            returnPath: '/orders/42',
        })
    })

    it('builds context only for destinations that declare v1', () => {
        const url = buildContextualLaunchUrl({
            appId: 'app', name: 'App', url: 'https://app.bigso.cloud',
            launchUrl: 'https://app.bigso.cloud/launch', launchProtocol: 'bigso-context-launch-v1',
        }, tenantId, '/orders')
        expect(url).toContain('/launch?')
        expect(url).toContain(`tenant_hint=${tenantId}`)
        expect(url).toContain('return_path=%2Forders')
    })

    it('falls back to the registered URL for legacy destinations', () => {
        expect(buildContextualLaunchUrl({ appId: 'app', name: 'App', url: 'https://app.bigso.cloud' }, tenantId))
            .toBe('https://app.bigso.cloud/')
    })

    it('starts authorization with a top-level redirect and destination-owned PKCE', async () => {
        const adapter = new ContextualLaunchAdapter({
            clientId: 'app-id', ssoOrigin: 'https://auth.bigso.cloud', jwksUrl: 'https://api.bigso.cloud/jwks',
            redirectUri: 'https://destination.example/auth/callback', onAuthenticated: vi.fn(), navigate: vi.fn(),
        })
        await expect(adapter.launch(`?tenant_hint=${tenantId}&return_path=%2Fhome`)).resolves.toBe('redirected')
        const assigned = vi.mocked(window.location.assign).mock.calls[0][0] as string
        const url = new URL(assigned)
        expect(url.pathname).toBe('/auth/launch')
        expect(url.searchParams.get('tenant_id')).toBe(tenantId)
        expect(url.searchParams.get('code_challenge_method')).toBe('S256')
        expect(assigned).not.toContain('code_verifier')
    })

    it('consumes a state-bound callback once and removes credentials from the URL', async () => {
        const authenticated = vi.fn()
        const adapter = new ContextualLaunchAdapter({
            clientId: 'app-id', ssoOrigin: 'https://auth.bigso.cloud', jwksUrl: 'https://api.bigso.cloud/jwks',
            redirectUri: 'https://destination.example/auth/callback', onAuthenticated: authenticated, navigate: vi.fn(),
        })
        await adapter.launch(`?tenant_hint=${tenantId}&return_path=%2Forders`)
        const assigned = new URL(vi.mocked(window.location.assign).mock.calls[0][0] as string)
        const state = assigned.searchParams.get('state')!
        await adapter.complete(`?payload=signed-response&state=${state}`)
        expect(authenticated).toHaveBeenCalledWith(expect.objectContaining({
            state, signed_payload: 'signed-response', codeVerifier: expect.any(String),
        }), '/orders')
        expect(sessionStorage.getItem('bigso_context_launch_v1')).toBeNull()
        await expect(adapter.complete(`?payload=signed-response&state=${state}`))
            .rejects.toThrow('invalid_launch_context')
    })
})
