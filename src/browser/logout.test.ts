import { describe, expect, it, vi } from 'vitest'
import { logoutApplication, logoutGlobally } from './logout'

describe('browser logout helpers', () => {
    it('performs application logout without external navigation', async () => {
        const navigate = vi.fn()
        const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
            success: true,
            scope: 'application',
        }), { status: 200 }))

        await logoutApplication({ fetch: fetcher, navigate })

        expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({ scope: 'application' })
        expect(navigate).not.toHaveBeenCalled()
    })

    it('only navigates global logout to the configured Identity origin', async () => {
        const navigate = vi.fn()
        const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
            success: true,
            scope: 'global',
            continueUrl: 'https://auth.bigso.cloud/auth/sign-out?state=one',
            state: 'one',
        }), { status: 200 }))

        await logoutGlobally({
            fetch: fetcher,
            navigate,
            identityOrigin: 'https://auth.bigso.cloud',
            storage: { setItem: vi.fn() },
        })

        expect(navigate).toHaveBeenCalledWith('https://auth.bigso.cloud/auth/sign-out?state=one')
    })

    it('rejects an untrusted global continuation', async () => {
        const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
            success: true,
            scope: 'global',
            continueUrl: 'https://attacker.example/sign-out',
            state: 'one',
        }), { status: 200 }))

        await expect(logoutGlobally({
            fetch: fetcher,
            identityOrigin: 'https://auth.bigso.cloud',
            storage: { setItem: vi.fn() },
        })).rejects.toThrow('Untrusted global logout continuation')
    })
})
