import {
    CONTEXTUAL_LAUNCH_PROTOCOL,
    type ContextualLaunchAdapterOptions,
    type ContextualLaunchApplication,
    type ContextualLaunchContext,
} from '../types'
import { generateRandomId, generateVerifier, sha256Base64Url } from '../utils/crypto'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const TRANSACTION_KEY = 'bigso_context_launch_v1'
const TRANSACTION_TTL_MS = 5 * 60 * 1000

interface BrowserLaunchTransaction {
    state: string
    nonce: string
    verifier: string
    returnPath: string
    createdAt: number
}

export function normalizeReturnPath(value: string | null | undefined, fallback = '/'): string {
    if (!value || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return fallback
    try {
        const parsed = new URL(value, 'https://launch.invalid')
        if (parsed.origin !== 'https://launch.invalid') return fallback
        return `${parsed.pathname}${parsed.search}${parsed.hash}`
    } catch {
        return fallback
    }
}

export function parseContextualLaunch(search: string, fallback = '/'): ContextualLaunchContext {
    const params = new URLSearchParams(search)
    const tenantHint = params.get('tenant_hint') || undefined
    return {
        tenantHint: tenantHint && UUID.test(tenantHint) ? tenantHint : undefined,
        returnPath: normalizeReturnPath(params.get('return_path'), fallback),
        correlationId: params.get('correlation_id') || generateRandomId(),
    }
}

export function buildContextualLaunchUrl(
    application: ContextualLaunchApplication,
    tenantId: string,
    returnPath?: string,
    correlationId = generateRandomId(),
): string {
    const base = application.launchProtocol === CONTEXTUAL_LAUNCH_PROTOCOL && application.launchUrl
        ? application.launchUrl
        : application.url
    const url = new URL(base)
    if (application.launchProtocol === CONTEXTUAL_LAUNCH_PROTOCOL && application.launchUrl) {
        if (!UUID.test(tenantId)) throw new Error('tenantId must be a UUID')
        url.searchParams.set('tenant_hint', tenantId)
        url.searchParams.set('correlation_id', correlationId)
        if (returnPath) url.searchParams.set('return_path', normalizeReturnPath(returnPath))
    }
    return url.toString()
}

export class ContextualLaunchAdapter {
    constructor(private readonly options: ContextualLaunchAdapterOptions) {}

    async launch(search = window.location.search): Promise<'reused' | 'redirected'> {
        const context = parseContextualLaunch(search, this.options.defaultReturnPath)
        if (context.tenantHint && this.options.isSessionReusable
            && await this.options.isSessionReusable(context.tenantHint)) {
            this.options.navigate(context.returnPath)
            return 'reused'
        }
        if (!context.tenantHint) throw new Error('invalid_launch_context')
        if (!this.options.redirectUri) throw new Error('redirectUri is required for contextual launch')

        const state = generateRandomId()
        const nonce = generateRandomId()
        const verifier = generateVerifier(48)
        const challenge = await sha256Base64Url(verifier)
        const transaction: BrowserLaunchTransaction = {
            state, nonce, verifier, returnPath: context.returnPath, createdAt: Date.now(),
        }
        sessionStorage.setItem(TRANSACTION_KEY, JSON.stringify(transaction))

        const authorizeUrl = new URL(this.options.authorizationPath ?? '/auth/launch', this.options.ssoOrigin)
        authorizeUrl.searchParams.set('app_id', this.options.clientId)
        authorizeUrl.searchParams.set('tenant_id', context.tenantHint)
        authorizeUrl.searchParams.set('redirect_uri', this.options.redirectUri)
        authorizeUrl.searchParams.set('state', state)
        authorizeUrl.searchParams.set('nonce', nonce)
        authorizeUrl.searchParams.set('code_challenge', challenge)
        authorizeUrl.searchParams.set('code_challenge_method', 'S256')
        authorizeUrl.searchParams.set('correlation_id', context.correlationId)
        window.location.assign(authorizeUrl.toString())
        return 'redirected'
    }

    async complete(search = window.location.search): Promise<void> {
        const params = new URLSearchParams(search)
        const state = params.get('state')
        const signedPayload = params.get('payload')
        const raw = sessionStorage.getItem(TRANSACTION_KEY)
        sessionStorage.removeItem(TRANSACTION_KEY)
        if (!raw || !state || !signedPayload) throw new Error('invalid_launch_context')

        const transaction = JSON.parse(raw) as BrowserLaunchTransaction
        if (transaction.state !== state || Date.now() - transaction.createdAt > TRANSACTION_TTL_MS) {
            throw new Error('authorization_expired')
        }
        history.replaceState({}, document.title, window.location.pathname)
        await this.options.onAuthenticated({
            code: '', state, nonce: transaction.nonce, codeVerifier: transaction.verifier,
            signed_payload: signedPayload,
        }, transaction.returnPath)
    }
}
