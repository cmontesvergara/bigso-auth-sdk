import { jwtVerify, createRemoteJWKSet } from 'jose'
import type { SsoTokenPayload } from '../types'

export async function verifySignedPayload(
    token: string,
    jwksUrl: string,
    expectedAudience: string
) {
    const JWKS = createRemoteJWKSet(new URL(jwksUrl))
    const { payload } = await jwtVerify(token, JWKS, {
        audience: expectedAudience
    })
    return payload
}

export async function verifyAccessToken(
    accessToken: string,
    jwksUrl: string
): Promise<SsoTokenPayload> {
    const JWKS = createRemoteJWKSet(new URL(jwksUrl))
    const { payload } = await jwtVerify(accessToken, JWKS)

    if (!payload.sub || !payload.jti) {
        throw new Error('Invalid token structure: missing sub or jti')
    }

    return {
        sub: payload.sub as string,
        jti: payload.jti as string,
        iss: payload.iss as string,
        aud: (payload.aud as string) || '',
        exp: payload.exp as number,
        iat: payload.iat as number,
        tenants: (payload as any).tenants || [],
        systemRole: (payload as any).systemRole || 'user',
        scope: (payload as any).scope,
        deviceFingerprint: (payload as any).deviceFingerprint,
    }
}