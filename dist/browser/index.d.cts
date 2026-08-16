import { B as BigsoAuthOptions, a as BigsoAuthResult, C as ContextualLaunchAdapterOptions, b as ContextualLaunchApplication, c as ContextualLaunchContext, d as BrowserLogoutOptions, L as LogoutResult } from '../types-DPeoi2iF.cjs';
export { e as CONTEXTUAL_LAUNCH_PROTOCOL, f as ContextualLaunchErrorCode, g as LogoutRequest, h as LogoutScope } from '../types-DPeoi2iF.cjs';

declare class EventEmitter {
    private events;
    on(event: string, handler: (data?: any) => void): void;
    off(event: string, handler: (data?: any) => void): void;
    emit(event: string, data?: any): void;
}

declare class BigsoAuth extends EventEmitter {
    private options;
    private iframe?;
    private authCompleted;
    private requestId;
    private timeoutId?;
    private messageListener?;
    private abortController?;
    private hostEl?;
    private shadowRoot?;
    private overlayEl?;
    private loginInProgress;
    constructor(options: BigsoAuthOptions);
    login(): Promise<BigsoAuthResult>;
    abort(): void;
    private createUI;
    private closeUI;
    private getOverlayStyles;
    private buildFallbackUrl;
    private debug;
}

declare function normalizeReturnPath(value: string | null | undefined, fallback?: string): string;
declare function parseContextualLaunch(search: string, fallback?: string): ContextualLaunchContext;
declare function buildContextualLaunchUrl(application: ContextualLaunchApplication, tenantId: string, returnPath?: string, correlationId?: string): string;
declare class ContextualLaunchAdapter {
    private readonly options;
    constructor(options: ContextualLaunchAdapterOptions);
    launch(search?: string): Promise<'reused' | 'redirected'>;
    complete(search?: string): Promise<void>;
}

declare function logout(options: BrowserLogoutOptions): Promise<LogoutResult>;
declare function logoutApplication(options: Omit<BrowserLogoutOptions, 'scope'>): Promise<LogoutResult>;
declare function logoutGlobally(options: Omit<BrowserLogoutOptions, 'scope'>): Promise<LogoutResult>;

export { BigsoAuth, BigsoAuthOptions, BigsoAuthResult, BrowserLogoutOptions, ContextualLaunchAdapter, ContextualLaunchAdapterOptions, ContextualLaunchApplication, ContextualLaunchContext, LogoutResult, buildContextualLaunchUrl, logout, logoutApplication, logoutGlobally, normalizeReturnPath, parseContextualLaunch };
