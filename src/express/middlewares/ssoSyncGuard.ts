import type { Request, Response, NextFunction } from 'express';
import { promises as dns } from 'dns';

export interface SsoSyncGuardOptions {
    ssoBackendUrl: string;
    isProduction?: boolean;
}

export function ssoSyncGuardMiddleware(options: SsoSyncGuardOptions) {
    const isProduction = options.isProduction ?? process.env.NODE_ENV === 'production';

    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            // 1. HTTPS Check
            const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
            if (!isSecure && isProduction) {
                console.warn("⚠️  [BigsoAuthSDK] Blocked non-HTTPS sync request");
                res.status(403).json({ error: "HTTPS required" });
                return;
            }

            // 2. DNS/IP Check
            const clientIp = req.ip || req.socket.remoteAddress || '';

            // Allow localhost/loopback for development
            const isLoopback = clientIp === '::1' || clientIp === '127.0.0.1' || clientIp === '::ffff:127.0.0.1';

            if (!isProduction && isLoopback) {
                return next();
            }

            const ssoUrl = new URL(options.ssoBackendUrl);
            const ssoHostname = ssoUrl.hostname;

            // Resolve IPs of the SSO Backend
            const ssoIps = await dns.resolve4(ssoHostname).catch(() => [] as string[]);

            // Handle IPv6 mapped IPv4
            const cleanClientIp = clientIp.replace(/^.*:/, '');

            const isPrivateIp =
                cleanClientIp.startsWith('10.') ||
                cleanClientIp.startsWith('192.168.') ||
                (cleanClientIp.startsWith('172.') &&
                    parseInt(cleanClientIp.split('.')[1], 10) >= 16 &&
                    parseInt(cleanClientIp.split('.')[1], 10) <= 31);

            if (!ssoIps.includes(cleanClientIp) && !isPrivateIp) {
                console.warn(`⛔️ [BigsoAuthSDK] Blocked sync request from unauthorized IP: ${clientIp}`);
                res.status(403).json({ error: "Unauthorized origin" });
                return;
            }

            next();
        } catch (error) {
            console.error("❌ [BigsoAuthSDK] Sync Guard Validation Error:", error instanceof Error ? error.message : error);
            res.status(500).json({ error: "Security validation failed" });
        }
    };
}
