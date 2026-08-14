import { afterEach, describe, expect, it, vi } from 'vitest'
import { BigsoSsoClient } from './SsoClient'

const token = `header.${Buffer.from(JSON.stringify({ jti: 'session-one' })).toString('base64url')}.signature`

describe('BigsoSsoClient logout', () => {
    afterEach(() => vi.unstubAllGlobals())

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
})
