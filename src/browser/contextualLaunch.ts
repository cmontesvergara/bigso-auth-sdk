import { BigsoAuth } from './auth'
import {
    CONTEXTUAL_LAUNCH_PROTOCOL,
    type ContextualLaunchAdapterOptions,
    type ContextualLaunchApplication,
    type ContextualLaunchContext,
} from '../types'
import { generateRandomId } from '../utils/crypto'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

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

    async launch(search = window.location.search): Promise<'reused' | 'authenticated'> {
        const context = parseContextualLaunch(search, this.options.defaultReturnPath)
        if (context.tenantHint && this.options.isSessionReusable
            && await this.options.isSessionReusable(context.tenantHint)) {
            this.options.navigate(context.returnPath)
            return 'reused'
        }
        const auth = new BigsoAuth({ ...this.options, tenantId: context.tenantHint })
        const result = await auth.login()
        await this.options.onAuthenticated(result, context.returnPath)
        return 'authenticated'
    }
}
