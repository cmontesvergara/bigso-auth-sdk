/**
 * Simple logger for the auth-sdk.
 * Uses console under the hood but adds consistent prefixes and timestamps.
 */
export class SdkLogger {
    private context: string;

    constructor(context: string) {
        this.context = context;
    }

    private format(level: string, message: string, meta?: Record<string, any>): string {
        const ts = new Date().toISOString();
        const metaStr = meta ? ' | ' + JSON.stringify(redact(meta)) : '';
        return `[${ts}] [${level}] [${this.context}] ${message}${metaStr}`;
    }

    info(message: string, meta?: Record<string, any>): void {
        console.log(this.format('INFO', message, meta));
    }

    warn(message: string, meta?: Record<string, any>): void {
        console.warn(this.format('WARN', message, meta));
    }

    error(message: string, meta?: Record<string, any>): void {
        console.error(this.format('ERROR', message, meta));
    }
}

const sensitiveKey = /(authorization|cookie|password|secret|token|payload|hash|verifier|challenge)/i;
const jwtValue = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const bearerValue = /Bearer\s+[^\s,;]+/gi;

function redact(value: unknown, key?: string): unknown {
    if (key && sensitiveKey.test(key)) return '[REDACTED]';
    if (typeof value === 'string') {
        return value.replace(jwtValue, '[REDACTED]').replace(bearerValue, 'Bearer [REDACTED]');
    }
    if (Array.isArray(value)) return value.map((item) => redact(item));
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value as Record<string, unknown>)
                .map(([nestedKey, nestedValue]) => [nestedKey, redact(nestedValue, nestedKey)]),
        );
    }
    return value;
}
