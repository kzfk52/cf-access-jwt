<p>
  <a href="https://badge.fury.io/js/@kzfk52%2Fcf-access-jwt"><img src="https://badgen.net/npm/v/@kzfk52/cf-access-jwt" alt="npm version" height="18"></a>
</p>

# cf-access-jwt

Tiny lib for decoding Cloudflare Access JWTs and verifying signatures, using
native crypto APIs.

Currently supports `alg:'RS256'` only.

```js
const jwt = request.headers.get('Cf-Access-Jwt-Assertion');

// CloudFlare Zero Team id
const issuer = 'https://<your-team-name>.cloudflareaccess.com';
// CloudFlare Zero Access Application : Overview tab : Application Audience (AUD) Tag
const audience = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

const result = await parseJwt(jwt, issuer, audience);
if (!result.valid) {
  console.log(result.reason); // Invalid issuer/audience, expired, etc
} else {
  console.log(result.payload); // { iss, sub, aud, iat, exp, ...claims }
}
```

Code shamelessly stolen from: https://github.com/cfworker/cfworker/
