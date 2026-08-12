import { B as BigsoAuthOptions, a as BigsoAuthResult, C as ContextualLaunchAdapterOptions, b as ContextualLaunchApplication, c as ContextualLaunchContext } from '../types-BCrV2a1f.js';
export { d as CONTEXTUAL_LAUNCH_PROTOCOL, e as ContextualLaunchErrorCode } from '../types-BCrV2a1f.js';

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

declare function buildTopLevelAuthUrl(options: BigsoAuthOptions, codeChallenge: string, state: string, nonce: string): string;
declare function completeTopLevelAuth(options: Pick<BigsoAuthOptions, 'jwksUrl' | 'audience'>, search?: string): Promise<BigsoAuthResult>;

export { BigsoAuth, BigsoAuthOptions, BigsoAuthResult, ContextualLaunchAdapter, ContextualLaunchAdapterOptions, ContextualLaunchApplication, ContextualLaunchContext, buildContextualLaunchUrl, buildTopLevelAuthUrl, completeTopLevelAuth, normalizeReturnPath, parseContextualLaunch };
