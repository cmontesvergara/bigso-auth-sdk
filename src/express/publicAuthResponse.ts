import type {
    ActiveSessionApplication,
    SsoTenant,
    SsoUser,
} from '../types';

type UnknownRecord = Record<string, unknown>;

export interface PublicAuthResponse {
    success: boolean;
    expiresIn?: number;
    user?: SsoUser;
    currentTenant?: SsoTenant;
    relatedTenants?: SsoTenant[];
    activeApplications?: ActiveSessionApplication[];
    csrfToken?: string;
}

function isRecord(value: unknown): value is UnknownRecord {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(record: UnknownRecord, key: string): string | undefined {
    return typeof record[key] === 'string' ? record[key] : undefined;
}

function projectUser(value: unknown): SsoUser | undefined {
    if (!isRecord(value)) return undefined;
    const userId = stringValue(value, 'userId') ?? stringValue(value, 'id');
    const email = stringValue(value, 'email');
    if (!userId || !email) return undefined;
    return {
        userId,
        email,
        firstName: stringValue(value, 'firstName') ?? '',
        lastName: stringValue(value, 'lastName') ?? '',
    };
}

function projectPermissions(value: unknown): SsoTenant['permissions'] {
    if (!Array.isArray(value)) return [];
    return value.flatMap((permission) => {
        if (!isRecord(permission)) return [];
        const resource = stringValue(permission, 'resource');
        const action = stringValue(permission, 'action');
        return resource && action ? [{ resource, action }] : [];
    });
}

function projectTenant(value: unknown): SsoTenant | undefined {
    if (!isRecord(value)) return undefined;
    const id = stringValue(value, 'id');
    if (!id) return undefined;
    return {
        id,
        name: stringValue(value, 'name') ?? '',
        slug: stringValue(value, 'slug') ?? '',
        role: stringValue(value, 'role') ?? '',
        permissions: projectPermissions(value.permissions),
    };
}

function projectApplication(value: unknown): ActiveSessionApplication | undefined {
    if (!isRecord(value)) return undefined;
    const appId = stringValue(value, 'appId');
    const name = stringValue(value, 'name');
    if (!appId || !name) return undefined;
    return {
        appId,
        name,
        logoUrl: stringValue(value, 'logoUrl') ?? null,
    };
}

/**
 * Builds the only authentication/session shape that may cross into browser JavaScript.
 * Never spread upstream Identity responses here: new internal fields must remain private by default.
 */
export function projectPublicAuthResponse(value: unknown): PublicAuthResponse {
    const input = isRecord(value) ? value : {};
    const tokens = isRecord(input.tokens) ? input.tokens : {};
    const expiresIn = typeof tokens.expiresIn === 'number'
        ? tokens.expiresIn
        : typeof input.expiresIn === 'number'
            ? input.expiresIn
            : undefined;
    const user = projectUser(input.user);
    const currentTenant = projectTenant(input.currentTenant);
    const relatedTenants = Array.isArray(input.relatedTenants)
        ? input.relatedTenants.flatMap((tenant) => projectTenant(tenant) ?? [])
        : undefined;
    const activeApplications = Array.isArray(input.activeApplications)
        ? input.activeApplications.flatMap((application) => projectApplication(application) ?? [])
        : undefined;
    const csrfToken = stringValue(input, 'csrfToken');

    return {
        success: input.success !== false,
        ...(expiresIn === undefined ? {} : { expiresIn }),
        ...(user ? { user } : {}),
        ...(currentTenant ? { currentTenant } : {}),
        ...(relatedTenants ? { relatedTenants } : {}),
        ...(activeApplications ? { activeApplications } : {}),
        ...(csrfToken ? { csrfToken } : {}),
    };
}
