import { Router } from 'express';
import { ssoSyncGuardMiddleware } from '../middlewares/ssoSyncGuard';

export interface SsoSyncRouterOptions {
    resources: any[];
    appId: string;
    ssoBackendUrl: string;
    isProduction?: boolean;
}

export function createSsoSyncRouter(options: SsoSyncRouterOptions): Router {
    const router = Router();

    /**
     * GET /resources
     * Expose resources for SSO synchronization (Pull Model)
     */
    router.get('/resources', ssoSyncGuardMiddleware({
        ssoBackendUrl: options.ssoBackendUrl,
        isProduction: options.isProduction,
    }), (req: import('express').Request, res: import('express').Response) => {
        try {
            res.json({
                success: true,
                resources: options.resources,
                meta: {
                    appId: options.appId,
                    count: options.resources.length,
                    timestamp: new Date().toISOString(),
                },
            });
        } catch (error: any) {
            console.error("❌ [BigsoAuthSDK] Error in sync endpoint:", error.message);
            res.status(500).json({ error: error.message });
        }
    });

    return router;
}
