import { DecodedJwt } from "./types.js";
import { base64url } from "rfc4648";

// from @cfworker/base64url/src/decode.js
function decode(s: string): string {
  return new TextDecoder().decode(base64url.parse(s, { loose: true }));
}
/**
 * Decode a JWT into header, payload, and signature components.
 */
export function decodeJwt(token: string): DecodedJwt {
  const [header, payload, signature] = token.split(".");
  return {
    header: JSON.parse(decode(header)),
    payload: JSON.parse(decode(payload)),
    signature: base64url.parse(signature, { loose: true }),
    raw: { header, payload, signature },
  };
}
