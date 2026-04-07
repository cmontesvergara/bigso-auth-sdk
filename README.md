# @bigso/auth-sdk

SDK oficial de autenticación para Bigso SSO v2. Flujo basado en JWT Bearer tokens con PKCE, comunicación por iframe seguro, y validación JWKS.

## Características

- **Flujo PKCE completo** — codeVerifier se expone al consuming app para enviar al backend
- **JWT Bearer tokens** — accessToken + refreshToken con revoke y rotación automática
- **Comunicación por iframe** con postMessage v2.3 y validación de origen
- **JWS verification** en frontend con JWKS remoto
- **3 entry points**: Browser, Node.js, Express middleware
- **Server-to-server** login, exchange, refresh, logout via API v2

## Instalación

```bash
npm install @bigso/auth-sdk
```

## Arquitectura v2

```
┌──────────────┐     postMessage (v2.3)     ┌──────────────┐
│   App Web     │◄──────────────────────────►│  SSO Portal   │
│  (consuming)  │  sso-init / sso-success    │  (iframe)     │
└──────┬───────┘                             └──────┬───────┘
       │                                            │
       │ 1. auth.login() → codeVerifier             │
       │ 2. POST /exchange-v2-pkce                  │
       │    { code, codeVerifier }                  │
       ▼                                            ▼
┌──────────────┐     POST /api/v2/auth/exchange    ┌──────────────┐
│  App Backend  │──────────────────────────────────►│  SSO Core     │
│  (Express)   │◄─────────────────────────────────│  (API v2)     │
│              │     { accessToken, refreshToken }  │              │
└──────────────┘                                   └──────────────┘
```

## Uso

### Browser (iframe login)

```typescript
import { BigsoAuth } from '@bigso/auth-sdk';

const auth = new BigsoAuth({
  clientId: 'crm',
  ssoOrigin: 'https://sso.bigso.co',
  jwksUrl: 'https://sso.bigso.co/.well-known/jwks.json',
});

auth.on('success', async (result) => {
  // result.code         → authorization code
  // result.codeVerifier → PKCE verifier (send to your backend!)
  // result.signed_payload → JWS signed payload
  // result.state        → matches your original state
  // result.nonce        → matches your original nonce

  // Send to your backend:
  const response = await fetch('/api/auth/exchange-v2-pkce', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      payload: result.signed_payload,
    }),
  });
});

auth.login();
```

### Express backend

```typescript
import { BigsoSsoClient } from '@bigso/auth-sdk/node';
import { createSsoAuthRouter, ssoAuthMiddleware } from '@bigso/auth-sdk/express';

const ssoClient = new BigsoSsoClient({
  ssoBackendUrl: 'https://sso.bigso.co',
  ssoJwksUrl: 'https://sso.bigso.co/.well-known/jwks.json',
  appId: 'crm',
});

// Auth routes: /exchange, /exchange-v2, /session, /refresh, /logout
app.use('/api/auth', createSsoAuthRouter({
  ssoClient,
  frontendUrl: 'https://myapp.com',
}));

// Protected routes: validates Bearer JWT token
app.get('/api/protected', ssoAuthMiddleware({ ssoClient }), (req, res) => {
  res.json({ user: req.user, tenant: req.tenant });
});
```

### Node.js (server-to-server)

```typescript
import { BigsoSsoClient } from '@bigso/auth-sdk/node';

const client = new BigsoSsoClient({
  ssoBackendUrl: 'https://sso.bigso.co',
  ssoJwksUrl: 'https://sso.bigso.co/.well-known/jwks.json',
  appId: 'crm',
});

// Exchange authorization code with PKCE
const session = await client.exchangeCode('ac_abc123...', 'dBjftJeZ4CVP...');

// Validate an access token locally (no network call)
const payload = await client.validateAccessToken('eyJhbG...');

// Refresh tokens (uses httpOnly cookie)
const refreshed = await client.refreshTokens();

// Logout
await client.logout('eyJhbG...', true);  // revokeAll = true
```

## API Reference

### Browser: `BigsoAuth`

#### Constructor

| Param | Type | Required | Default | Description |
|---|---|---|---|---|
| `clientId` | `string` | Yes | — | App ID registered in SSO |
| `ssoOrigin` | `string` | Yes | — | SSO origin (e.g. `https://sso.bigso.co`) |
| `jwksUrl` | `string` | Yes | — | JWKS URL for JWS verification |
| `timeout` | `number` | No | `5000` | Timeout after `sso-ready` (ms) |
| `debug` | `boolean` | No | `false` | Debug logging |
| `redirectUri` | `string` | No | `''` | Redirect URI |
| `tenantHint` | `string` | No | `''` | Tenant hint for multi-tenant |

#### `auth.login()`

Returns `Promise<BigsoAuthResult>`:

| Field | Type | Description |
|---|---|---|
| `code` | `string` | Authorization code from SSO |
| `codeVerifier` | `string` | PKCE code verifier — send to backend |
| `state` | `string` | Matches your original state |
| `nonce` | `string` | Matches your original nonce |
| `signed_payload` | `string` | JWS signed payload |
| `tenant` | `SsoTenant` | Tenant data (if included) |

### Node: `BigsoSsoClient`

| Method | Description |
|---|---|
| `exchangeCode(code, codeVerifier)` | Exchange auth code for tokens via `/api/v2/auth/exchange` |
| `refreshTokens()` | Refresh tokens via `/api/v2/auth/refresh` (uses cookie) |
| `logout(accessToken, revokeAll?)` | Revoke session via `/api/v2/auth/logout` |
| `validateAccessToken(token)` | Verify JWT locally against JWKS |
| `verifySignedPayload(token, audience)` | Verify JWS signed payload |

### Express: `createSsoAuthRouter(options)`

| Route | Method | Description |
|---|---|---|
| `/exchange` | POST | `{code, codeVerifier}` → v2 exchange |
| `/exchange-v2` | POST | `{payload}` → verify JWS, then v2 exchange |
| `/session` | GET | Validate Bearer token, return user data |
| `/refresh` | POST | Proxy to `/api/v2/auth/refresh` |
| `/logout` | POST | Bearer token → `/api/v2/auth/logout` |

### Express: `ssoAuthMiddleware({ ssoClient })`

Reads `Authorization: Bearer <token>`, validates JWT against JWKS, populates `req.user`, `req.tenant`, `req.tokenPayload`.

## Flujo PKCE completo

```
1. Browser SDK genera: state, nonce, codeVerifier
2. Browser SDK computa: codeChallenge = SHA256(codeVerifier)
3. Browser SDK → iframe: {codeChallenge, state, nonce}
4. Iframe → SSO Core: POST /api/v2/auth/authorize (con codeChallenge)
5. Iframe → Browser SDK: {code, state} (firmado como JWS)
6. Browser SDK verifica JWS, valida state y nonce
7. Browser SDK retorna {code, codeVerifier} al consuming app
8. Consuming app → su backend: POST /exchange-v2-pkce {payload, codeVerifier}
9. Backend verifica JWS, extrae code, llama /api/v2/auth/exchange {code, appId, codeVerifier}
10. SSO Core verifica: SHA256(codeVerifier) === codeChallenge → emite tokens
```

## Seguridad

- **PKCE**: codeVerifier nunca sale del browser hasta el paso 7, pero jamás se envía al SSO iframe
- **JWS**: El signed_payload se verifica contra JWKS en frontend y backend
- **state + nonce**: Validados en ambos lados para prevenir CSRF y replay
- **JWT Bearer**: Access tokens validados localmente contra JWKS, revocables en Redis/PG
- **httpOnly cookies**: Refresh tokens via cookie, nunca accesibles via JS

## Desarrollo

```bash
npm run build   # ESM + CJS + types → dist/
npm run dev     # watch mode
npm run lint    # eslint
npm test        # vitest
```

## Changelog

### v0.5.0 (2026-04-07) — Full v2

**Breaking changes:**
- All v1 API endpoints removed (`/api/v1/auth/token`, `/api/v1/auth/verify-session`, etc.)
- `SsoSessionData`, `SsoRefreshData`, `SsoExchangeResponse` types removed
- `ssoAuthMiddleware` now validates Bearer JWT (no cookies)
- Express routes use v2 endpoints exclusively
- `BigsoSsoClient` methods renamed/changed

**New features:**
- `BigsoAuthResult.codeVerifier` — PKCE verifier exposed for backend exchange
- `BigsoSsoClient.exchangeCode(code, codeVerifier)` — PKCE exchange via `/api/v2/auth/exchange`
- `BigsoSsoClient.refreshTokens()` — via `/api/v2/auth/refresh`
- `BigsoSsoClient.logout(accessToken)` — via `/api/v2/auth/logout`
- `BigsoSsoClient.validateAccessToken(token)` — Local JWT verification against JWKS
- Express `/exchange-v2-pkce` route with full PKCE support
- Express `/refresh` and `/logout` routes for v2 API
- `ssoAuthMiddleware` validates Bearer JWT tokens locally

### v0.4.0 (2026-03-23)
- SSO v2.3 protocol support (iframe postMessage)
- PKCE, JWS verification, nonce validation
- Timeout reactive (starts after `sso-ready`)

## Licencia

MIT © Bigso