import { expect } from "chai";
import { describe, it } from "mocha";
import { decodeJwt } from "../src/decode.js";
import { base64url } from "rfc4648";

describe("decodeJwt", () => {
  const encoded =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const [rawHeader, rawPayload, rawSignature] = encoded.split(".");

  it("decodes a JWT", () => {
    expect(decodeJwt(encoded)).to.eql({
      header: {
        alg: "HS256",
        typ: "JWT",
      },
      payload: {
        sub: "1234567890",
        name: "John Doe",
        iat: 1516239022,
      },
      signature: base64url.parse(rawSignature, { loose: true }),
      raw: {
        header: rawHeader,
        payload: rawPayload,
        signature: rawSignature,
      },
    });
  });
});
