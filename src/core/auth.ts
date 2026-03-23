import { sha256Base64Url, generateVerifier, generateRandomId } from '../utils/crypto'
import { EventEmitter } from '../utils/events'
import { verifySignedPayload } from '../utils/jws'
import type { BigsoAuthOptions, SsoInitPayload, SsoSuccessPayload, SsoErrorPayload } from '../types'

export class BigsoAuth extends EventEmitter {
    private options: Required<BigsoAuthOptions>
    private iframe?: HTMLIFrameElement
    private authCompleted = false
    private requestId = generateRandomId()
    private timeoutId?: number
    private messageListener?: (event: MessageEvent) => void
    private abortController?: AbortController

    // UI elements (Shadow DOM)
    private hostEl?: HTMLDivElement
    private shadowRoot?: ShadowRoot
    private overlayEl?: HTMLDivElement
    private loginInProgress = false

    constructor(options: BigsoAuthOptions) {
        super()
        this.options = {
            timeout: 5000,           // por defecto 5s (estándar v2.3)
            debug: false,
            redirectUri: '',
            tenantHint: '',
            theme: 'light',
            ...options
        }
    }

    /**
     * Inicia el flujo de autenticación.
     * @returns Promise que resuelve con el payload decodificado del JWS (solo para información; el backend debe validar)
     */
    async login(): Promise<any> {
        // Guard anti-duplicado: prevenir múltiples instancias
        if (this.loginInProgress) {
            this.debug('login() ya en curso, ignorando llamada duplicada')
            return Promise.reject(new Error('Login already in progress'))
        }
        this.loginInProgress = true
        this.authCompleted = false

        // Generar y almacenar contexto de la transacción
        const state = generateRandomId()
        const nonce = generateRandomId()
        const verifier = generateVerifier()
        const requestId = this.requestId

        sessionStorage.setItem('sso_ctx', JSON.stringify({ state, nonce, verifier, requestId }))

        // Crear y mostrar UI (overlay + iframe)
        this.createUI()

        return new Promise((resolve, reject) => {
            // Usar AbortController para poder cancelar la promesa externamente
            this.abortController = new AbortController()
            const { signal } = this.abortController

            const cleanup = () => {
                if (this.timeoutId) clearTimeout(this.timeoutId)
                if (this.messageListener) window.removeEventListener('message', this.messageListener)
                this.iframe?.remove()
                this.iframe = undefined
                this.authCompleted = true
                this.loginInProgress = false
            }

            // Listener de mensajes postMessage
            this.messageListener = async (event: MessageEvent) => {
                // Validación 1: origen exacto (whitelist implícita)
                if (event.origin !== this.options.ssoOrigin) {
                    this.debug('Ignorado mensaje de origen no autorizado:', event.origin)
                    return
                }

                const msg = event.data
                this.debug('Mensaje recibido:', msg)

                // Validación 2: requestId debe coincidir (si está presente)
                if (msg.requestId && msg.requestId !== requestId) {
                    this.debug('requestId no coincide, ignorado')
                    return
                }

                // Evento sso-ready: iniciar timeout y enviar sso-init
                if (msg.type === 'sso-ready') {
                    this.debug('sso-ready recibido, iniciando timeout y enviando sso-init')

                    // Iniciar timeout reactivo (estándar v2.3 sección 7)
                    this.timeoutId = window.setTimeout(() => {
                        if (!this.authCompleted) {
                            this.debug('Timeout alcanzado, activando fallback')
                            this.closeUI()
                            cleanup()
                            this.emit('fallback')
                            window.location.href = this.buildFallbackUrl()
                            reject(new Error('Timeout'))
                        }
                    }, this.options.timeout)

                    // Preparar payload sso-init
                    const codeChallenge = await sha256Base64Url(verifier)
                    const initPayload: SsoInitPayload = {
                        state,
                        nonce,
                        code_challenge: codeChallenge,
                        code_challenge_method: 'S256',
                        origin: window.location.origin,
                        ...(this.options.redirectUri && { redirect_uri: this.options.redirectUri }),
                        ...(this.options.tenantHint && { tenant_hint: this.options.tenantHint }),
                        timeout_ms: this.options.timeout  // pasar el timeout configurado (opcional)
                    }

                    // Enviar sso-init al iframe
                    this.iframe?.contentWindow?.postMessage({
                        v: '2.3',                     // versión del protocolo (estándar v2.3)
                        source: '@app/widget',
                        type: 'sso-init',
                        requestId: this.requestId,
                        payload: initPayload
                    }, this.options.ssoOrigin)

                    this.emit('ready')
                    return
                }

                // Evento sso-success
                if (msg.type === 'sso-success') {
                    this.debug('sso-success recibido')
                    clearTimeout(this.timeoutId)

                    try {
                        const payload = msg.payload as SsoSuccessPayload
                        const ctx = JSON.parse(sessionStorage.getItem('sso_ctx') || '{}')

                        // Validar state (comparación en tiempo constante simulada)
                        if (payload.state !== ctx.state) {
                            throw new Error('Invalid state')
                        }

                        // Verificar firma JWS con jose
                        const decoded = await verifySignedPayload(
                            payload.signed_payload,
                            this.options.jwksUrl,
                            window.location.origin  // aud esperado
                        )

                        // Validar nonce (estándar v2.3 sección 8 paso 8)
                        if (decoded.nonce !== ctx.nonce) {
                            throw new Error('Invalid nonce')
                        }

                        this.debug('JWS válido, payload:', decoded)

                        // Cerrar overlay con animación, luego resolver
                        this.closeUI()
                        cleanup()
                        this.emit('success', decoded)
                        resolve(decoded)
                    } catch (err) {
                        this.debug('Error en sso-success:', err)
                        this.closeUI()
                        cleanup()
                        this.emit('error', err)
                        reject(err)
                    }
                    return
                }

                // Evento sso-error
                if (msg.type === 'sso-error') {
                    const errorPayload = msg.payload as SsoErrorPayload
                    this.debug('sso-error recibido:', errorPayload)
                    clearTimeout(this.timeoutId)
                    this.closeUI()
                    cleanup()

                    // Manejo especial para version_mismatch (estándar v2.3 sección 3.4)
                    if (errorPayload.code === 'version_mismatch') {
                        this.emit('error', errorPayload)
                        window.location.href = this.buildFallbackUrl()
                        reject(new Error(`Version mismatch: expected ${errorPayload.expected_version}`))
                    } else {
                        this.emit('error', errorPayload)
                        reject(errorPayload)
                    }
                }

                // Evento sso-close (el iframe pide cerrar el modal)
                if (msg.type === 'sso-close') {
                    this.debug('sso-close recibido')
                    this.closeUI()
                    cleanup()
                    reject(new Error('Login cancelled by user'))
                }
            }

            window.addEventListener('message', this.messageListener)

            // Manejar señal de aborto (cancelación externa)
            signal.addEventListener('abort', () => {
                this.debug('Operación abortada')
                this.closeUI()
                cleanup()
                reject(new Error('Login aborted'))
            })
        })
    }

    /** Cancela el flujo de autenticación en curso */
    abort() {
        this.abortController?.abort()
    }

    // ─── UI Management ───────────────────────────────────────────────

    /**
     * Crea (o reutiliza) el overlay con Shadow DOM y el iframe visible.
     * Patrón tomado del CDN widget v1: Shadow DOM para aislar estilos.
     */
    private createUI() {
        // Crear host y Shadow DOM si no existe
        if (!this.hostEl) {
            this.hostEl = document.createElement('div')
            this.hostEl.id = 'bigso-auth-host'
            this.shadowRoot = this.hostEl.attachShadow({ mode: 'open' })

            // Estilos encapsulados
            const style = document.createElement('style')
            style.textContent = this.getOverlayStyles()
            this.shadowRoot.appendChild(style)

            // Overlay
            this.overlayEl = document.createElement('div')
            this.overlayEl.className = 'sso-overlay'

            // Botón X de cierre
            const closeBtn = document.createElement('button')
            closeBtn.className = 'sso-close-btn'
            closeBtn.innerHTML = '&times;'
            closeBtn.setAttribute('aria-label', 'Cerrar modal')
            closeBtn.addEventListener('click', () => this.abort())
            this.overlayEl.appendChild(closeBtn)

            // Click fuera del iframe para cerrar
            this.overlayEl.addEventListener('click', (event) => {
                if (event.target === this.overlayEl) {
                    this.abort()
                }
            })

            this.shadowRoot.appendChild(this.overlayEl)
            document.body.appendChild(this.hostEl)
        }

        // Crear iframe (se destruye en cleanup, se recrea aquí)
        this.iframe = document.createElement('iframe')
        this.iframe.className = 'sso-frame'
        this.iframe.src = `${this.options.ssoOrigin}/auth/sign-in?v=2.3&client_id=${this.options.clientId}`
        this.iframe.setAttribute('title', 'SSO Login')
        this.overlayEl!.appendChild(this.iframe)
        this.debug('Iframe creado', this.iframe.src)

        // Mostrar overlay con animación
        this.overlayEl!.classList.remove('sso-closing')
        this.overlayEl!.style.display = 'flex'
    }

    /**
     * Cierra el overlay con animación suave (fadeOut + slideDown).
     * El overlay persiste en el DOM (solo se oculta).
     */
    private closeUI() {
        if (!this.overlayEl || this.overlayEl.style.display === 'none') return

        this.overlayEl.classList.add('sso-closing')

        // Esperar a que la animación termine (200ms)
        setTimeout(() => {
            if (this.overlayEl) {
                this.overlayEl.style.display = 'none'
                this.overlayEl.classList.remove('sso-closing')
            }
        }, 200)
    }

    /**
     * Estilos CSS encapsulados dentro del Shadow DOM.
     * Migrados del widget CDN v1 con las mismas animaciones y responsive.
     */
    private getOverlayStyles(): string {
        return `
            .sso-overlay {
                position: fixed;
                inset: 0;
                display: none;
                justify-content: center;
                align-items: center;
                background: rgba(0, 0, 0, 0.6);
                z-index: 999999;
                backdrop-filter: blur(4px);
                -webkit-backdrop-filter: blur(4px);
                animation: fadeIn 0.2s ease;
            }
            .sso-frame {
                width: 370px;
                height: 350px;
                border: none;
                border-radius: 16px;
                background: var(--card-bg, #fff);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.3);
                animation: slideUp 0.3s ease;
            }
            @media (max-width: 480px), (max-height: 480px) {
                .sso-frame {
                    width: 100%;
                    height: 100%;
                    border-radius: 0;
                }
            }
            .sso-close-btn {
                position: absolute;
                top: 12px;
                right: 12px;
                width: 32px;
                height: 32px;
                background: rgba(0, 0, 0, 0.4);
                color: white;
                border: none;
                border-radius: 50%;
                font-size: 24px;
                line-height: 1;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000000;
                transition: background 0.2s;
            }
            .sso-close-btn:hover {
                background: rgba(0, 0, 0, 0.8);
            }
            .sso-overlay.sso-closing {
                animation: fadeOut 0.2s ease forwards;
            }
            .sso-overlay.sso-closing .sso-frame {
                animation: slideDown 0.2s ease forwards;
            }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            @keyframes slideUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
            @keyframes fadeOut { from { opacity: 1; } to { opacity: 0; } }
            @keyframes slideDown { from { transform: translateY(0); opacity: 1; } to { transform: translateY(20px); opacity: 0; } }
        `
    }

    // ─── Helpers ──────────────────────────────────────────────────────

    private buildFallbackUrl(): string {
        const url = new URL(`${this.options.ssoOrigin}/authorize`)
        url.searchParams.set('client_id', this.options.clientId)
        url.searchParams.set('response_type', 'code')
        url.searchParams.set('redirect_uri', this.options.redirectUri || window.location.origin)
        url.searchParams.set('state', generateRandomId())
        url.searchParams.set('code_challenge_method', 'S256')
        return url.toString()
    }

    private debug(...args: any[]) {
        if (this.options.debug) {
            console.log('[BigsoAuth]', ...args)
        }
    }
}