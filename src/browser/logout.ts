import type { BrowserLogoutOptions, LogoutResult } from '../types'

export async function logout(options: BrowserLogoutOptions): Promise<LogoutResult> {
    if (options.scope !== 'application' && options.scope !== 'global') {
        throw new Error('Unsupported logout scope')
    }

    const fetcher = options.fetch ?? globalThis.fetch
    const endpoint = options.endpoint ?? '/api/auth/logout'
    await options.onTransitionStart?.()

    try {
        const response = await fetcher(endpoint, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope: options.scope }),
        })
        if (!response.ok) throw new Error(`Logout failed (status: ${response.status})`)

        const result = await response.json() as LogoutResult
        if (!result.success || result.scope !== options.scope) {
            throw new Error('Invalid logout response')
        }

        if (options.scope === 'global') {
            if (!result.continueUrl || !result.state || !options.identityOrigin) {
                throw new Error('Global logout requires an Identity continuation')
            }
            const continuation = new URL(result.continueUrl)
            if (continuation.origin !== new URL(options.identityOrigin).origin) {
                throw new Error('Untrusted global logout continuation')
            }
            ;(options.storage ?? window.sessionStorage).setItem('bigso_logout_state_v1', result.state)
            ;(options.navigate ?? ((url) => window.location.assign(url)))(continuation.toString())
        }

        return result
    } catch (cause) {
        const error = cause instanceof Error ? cause : new Error('Logout failed')
        await options.onTransitionError?.(error)
        throw error
    }
}

export function logoutApplication(options: Omit<BrowserLogoutOptions, 'scope'>): Promise<LogoutResult> {
    return logout({ ...options, scope: 'application' })
}

export function logoutGlobally(options: Omit<BrowserLogoutOptions, 'scope'>): Promise<LogoutResult> {
    return logout({ ...options, scope: 'global' })
}
