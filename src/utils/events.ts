// Emisor de eventos simple

export class EventEmitter {
    private events: Record<string, Array<(data?: any) => void>> = {}

    on(event: string, handler: (data?: any) => void) {
        if (!this.events[event]) this.events[event] = []
        this.events[event].push(handler)
    }

    off(event: string, handler: (data?: any) => void) {
        if (!this.events[event]) return
        this.events[event] = this.events[event].filter(h => h !== handler)
    }

    emit(event: string, data?: any) {
        this.events[event]?.forEach(fn => fn(data))
    }
}
