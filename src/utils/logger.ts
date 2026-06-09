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
        const metaStr = meta ? ' | ' + JSON.stringify(meta) : '';
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
