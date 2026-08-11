import { describe, expect, it } from 'vitest'
import { buildContextualLaunchUrl, normalizeReturnPath, parseContextualLaunch } from './contextualLaunch'

const tenantId = '6615ba1e-73ee-4c6c-a689-2a8359253988'

describe('contextual app launch v1', () => {
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
})
