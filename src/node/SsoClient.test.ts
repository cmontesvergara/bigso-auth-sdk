import { afterEach, describe, expect, it, vi } from 'vitest'
import { BigsoSsoClient } from './SsoClient'

const token = `header.${Buffer.from(JSON.stringify({ jti: 'session-one' })).toString('base64url')}.signature`

describe('BigsoSsoClient logout', () => {
    afterEach(() => {
        vi.unstubAllGlobals()
        vi.restoreAllMocks()
    })

    it.each([
        [true, 'global'],
        [false, 'application'],
        [{ scope: 'global' } as const, 'global'],
        [{ scope: 'application' } as const, 'application'],
    ])('maps %o to the %s scope', async (input, expectedScope) => {
        const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
        vi.stubGlobal('fetch', fetcher)
        const client = new BigsoSsoClient({
            ssoBackendUrl: 'https://api.bigso.cloud/idp',
            appId: 'app-one',
        })

        await client.logout(token, input)

        const body = JSON.parse(fetcher.mock.calls[0][1].body)
        expect(body).toEqual({
            scope: expectedScope,
            isGlobal: expectedScope === 'global',
            sessionId: 'session-one',
        })
    })

    it('never writes refresh or access tokens to logs', async () => {
        const refreshToken = 'refresh-token-must-stay-secret'
        const accessToken = 'access-token-must-stay-secret'
        const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
            tokens: { refreshToken: 'rotated-refresh-secret', accessToken },
        }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
        vi.stubGlobal('fetch', fetcher)
        const log = vi.spyOn(console, 'log').mockImplementation(() => undefined)
        const error = vi.spyOn(console, 'error').mockImplementation(() => undefined)
        const client = new BigsoSsoClient({
            ssoBackendUrl: 'https://api.bigso.cloud/idp',
            appId: 'app-one',
        })

        await client.refreshTokens(refreshToken, 'tenant-one')

        const emitted = JSON.stringify([...log.mock.calls, ...error.mock.calls])
        expect(emitted).not.toContain(refreshToken)
        expect(emitted).not.toContain(accessToken)
        expect(emitted).not.toContain('rotated-refresh-secret')
    })
})
