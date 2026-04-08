// src/utils/jws.ts
import { jwtVerify, createRemoteJWKSet } from "jose";
async function verifySignedPayload(token, jwksUrl, expectedAudience) {
  const JWKS = createRemoteJWKSet(new URL(jwksUrl));
  const { payload } = await jwtVerify(token, JWKS, {
    audience: expectedAudience
  });
  return payload;
}
async function verifyAccessToken(accessToken, jwksUrl) {
  const JWKS = createRemoteJWKSet(new URL(jwksUrl));
  const { payload } = await jwtVerify(accessToken, JWKS);
  if (!payload.sub || !payload.jti) {
    throw new Error("Invalid token structure: missing sub or jti");
  }
  return {
    sub: payload.sub,
    jti: payload.jti,
    iss: payload.iss,
    aud: payload.aud || "",
    exp: payload.exp,
    iat: payload.iat,
    tenants: payload.tenants || [],
    systemRole: payload.systemRole || "user",
    deviceFingerprint: payload.deviceFingerprint
  };
}

export {
  verifySignedPayload,
  verifyAccessToken
};
