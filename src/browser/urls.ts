export function buildSsoFrameUrl(
    ssoOrigin: string,
    clientId: string,
    tenantId?: string
): string {
    const url = new URL('/auth/i-sign-in', ssoOrigin)
    url.searchParams.set('v', '2.3')
    url.searchParams.set('client_id', clientId)
    if (tenantId) url.searchParams.set('tenant_id', tenantId)
    return url.toString()
}
