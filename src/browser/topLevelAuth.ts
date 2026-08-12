import type { BigsoAuthOptions, BigsoAuthResult, SsoTenant } from '../types'
import { verifySignedPayload } from '../utils/jws'

export const EMBEDDED_AUTH_TRANSACTION_KEY = 'sso_ctx'

interface EmbeddedAuthTransaction {
    state: string
    nonce: string
    verifier: string
    requestId: string
    createdAt: number
}

export function buildTopLevelAuthUrl(
    options: BigsoAuthOptions,
    codeChallenge: string,
    state: string,
    nonce: string,
): string {
    const redirectUri = options.redirectUri || `${window.location.origin}${window.location.pathname}`
    const url = new URL('/auth/launch', options.ssoOrigin)
    url.searchParams.set('app_id', options.clientId)
    url.searchParams.set('redirect_uri', redirectUri)
    url.searchParams.set('state', state)
    url.searchParams.set('nonce', nonce)
    url.searchParams.set('code_challenge', codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
    if (options.tenantId) url.searchParams.set('tenant_id', options.tenantId)
    return url.toString()
}

export async function completeTopLevelAuth(
    options: Pick<BigsoAuthOptions, 'jwksUrl' | 'audience'>,
    search = window.location.search,
): Promise<BigsoAuthResult> {
    const params = new URLSearchParams(search)
    const state = params.get('state')
    const signedPayload = params.get('payload')
    const raw = sessionStorage.getItem(EMBEDDED_AUTH_TRANSACTION_KEY)
    if (!raw || !state || !signedPayload) throw new Error('invalid_launch_context')

    const transaction = JSON.parse(raw) as EmbeddedAuthTransaction
    sessionStorage.removeItem(EMBEDDED_AUTH_TRANSACTION_KEY)
    if (transaction.state !== state || Date.now() - transaction.createdAt > 5 * 60 * 1000) {
        throw new Error('authorization_expired')
    }
    const decoded = await verifySignedPayload(
        signedPayload,
        options.jwksUrl,
        options.audience ?? window.location.origin,
    )
    if (decoded.nonce !== transaction.nonce) throw new Error('Invalid nonce')
    history.replaceState({}, document.title, window.location.pathname)

    return {
        code: decoded.code as string,
        state: (decoded.state as string) || transaction.state,
        nonce: transaction.nonce,
        codeVerifier: transaction.verifier,
        signed_payload: signedPayload,
        tenant: decoded.tenant as SsoTenant | undefined,
        jti: decoded.jti as string | undefined,
        iss: decoded.iss as string | undefined,
        aud: typeof decoded.aud === 'string' ? decoded.aud : undefined,
        exp: decoded.exp as number | undefined,
        iat: decoded.iat as number | undefined,
    }
}
