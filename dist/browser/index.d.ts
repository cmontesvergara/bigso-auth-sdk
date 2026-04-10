import { B as BigsoAuthOptions, a as BigsoAuthResult } from '../types-K3V5MV8v.js';

declare class EventEmitter {
    private events;
    on(event: string, handler: Function): void;
    off(event: string, handler: Function): void;
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

export { BigsoAuth, BigsoAuthOptions, BigsoAuthResult };
