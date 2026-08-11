import { Router, type Request, type Response } from 'express'
import type { BigsoSsoClient } from '../../node/SsoClient'
import type { CookieConfig } from './createSsoAuthRouter'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export interface ContextualLaunchRouterOptions {
    ssoClient: BigsoSsoClient
    cookieConfig: Pick<CookieConfig, 'sessionName'>
}

export function createContextualLaunchRouter(options: ContextualLaunchRouterOptions): Router {
    const router = Router()

    router.get('/session', async (req: Request, res: Response) => {
        res.set('Cache-Control', 'no-store')
        const tenantHint = typeof req.query.tenant_hint === 'string' ? req.query.tenant_hint : ''
        if (!UUID.test(tenantHint)) {
            res.status(400).json({ reusable: false, error: 'invalid_launch_context' })
            return
        }
        const sessionId = req.cookies?.[options.cookieConfig.sessionName]
        if (!sessionId) {
            res.status(200).json({ reusable: false, error: 'session_required' })
            return
        }
        try {
            const client = options.ssoClient.getClientOptions()
            const session = await options.ssoClient.session(sessionId, client.appId)
            res.status(200).json({ reusable: session.currentTenant?.id === tenantHint })
        } catch {
            res.status(200).json({ reusable: false, error: 'session_required' })
        }
    })

    return router
}
