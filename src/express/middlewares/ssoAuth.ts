import type { Request, Response, NextFunction } from 'express';
import type { BigsoSsoClient } from '../../node/SsoClient';
import type { SsoSessionData } from '../../types';

export interface SsoAuthMiddlewareOptions {
    ssoClient: BigsoSsoClient;
    cookieName?: string;
    cookieDomain?: string;
    isProduction?: boolean;
    onSessionValidated?: (session: SsoSessionData, req: Request) => Promise<void> | void;
}

declare global {
    namespace Express {
        interface Request {
            user?: SsoSessionData['user'];
            tenant?: SsoSessionData['tenant'];
            ssoSession?: SsoSessionData;
        }
    }
}

export function ssoAuthMiddleware(options: SsoAuthMiddlewareOptions) {
    const cookieName = options.cookieName || 'sso_session';
    const isProduction = options.isProduction ?? process.env.NODE_ENV === 'production';

    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            let sessionToken = req.cookies?.[cookieName];
            let session: SsoSessionData | null = null;

            if (sessionToken) {
                session = await options.ssoClient.validateSessionToken(sessionToken);
            }

            if (!session) {
                // Token missing, invalid, or expired. Try to refresh.
                const refreshToken = req.cookies?.[`${cookieName}_refresh`];
                
                if (refreshToken) {
                    const newSessionData = await options.ssoClient.refreshAppSession(refreshToken);
                    
                    if (newSessionData) {
                        const sessionMaxAge = new Date(newSessionData.expiresAt).getTime() - Date.now();
                        const refreshMaxAge = newSessionData.refreshExpiresAt 
                            ? new Date(newSessionData.refreshExpiresAt).getTime() - Date.now() 
                            : 7 * 24 * 60 * 60 * 1000;

                        const sessionCookieOptions = {
                            httpOnly: true,
                            secure: isProduction,
                            sameSite: 'lax' as const,
                            path: '/',
                            maxAge: sessionMaxAge > 0 ? sessionMaxAge : 0,
                            ...(isProduction && options.cookieDomain ? { domain: options.cookieDomain } : {}),
                        };

                        const refreshCookieOptions = {
                            ...sessionCookieOptions,
                            maxAge: refreshMaxAge > 0 ? refreshMaxAge : 0,
                        };

                        res.cookie(cookieName, newSessionData.sessionToken, sessionCookieOptions);
                        res.cookie(`${cookieName}_refresh`, newSessionData.refreshToken, refreshCookieOptions);

                        // Re-validate with new token to get full payload
                        session = await options.ssoClient.validateSessionToken(newSessionData.sessionToken);
                    }
                }

                if (!session) {
                    res.clearCookie(cookieName);
                    res.clearCookie(`${cookieName}_refresh`);
                    
                    // Respond with 401 unauthenticated.
                    res.status(401).json({ error: "Session expired or invalid" });
                    return;
                }
            }

            // Sync Tenant locally if callback provided
            if (options.onSessionValidated) {
                await options.onSessionValidated(session, req);
            }

            // Attach data to request
            req.user = session.user;
            req.tenant = session.tenant; // Modifiable by onSessionValidated via req.tenant
            req.ssoSession = session;

            next();
        } catch (error) {
            console.error("❌ [BigsoAuthSDK] Authentication Middleware Error:", error instanceof Error ? error.message : error);
            res.status(500).json({ error: "Internal authentication error" });
        }
    };
}
