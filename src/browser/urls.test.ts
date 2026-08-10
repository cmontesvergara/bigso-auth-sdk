import { describe, expect, it } from 'vitest'
import { buildSsoFrameUrl } from './urls'

describe('buildSsoFrameUrl', () => {
    it('omits tenant_id for tenantless bootstrap', () => {
        const url = new URL(buildSsoFrameUrl('https://auth.bigso.co', 'mi-bigso'))

        expect(url.searchParams.has('tenant_id')).toBe(false)
    })

    it('preserves an explicit tenant hint', () => {
        const tenantId = '11111111-1111-4111-8111-111111111111'
        const url = new URL(buildSsoFrameUrl('https://auth.bigso.co', 'mi-bigso', tenantId))

        expect(url.searchParams.get('tenant_id')).toBe(tenantId)
    })
})
