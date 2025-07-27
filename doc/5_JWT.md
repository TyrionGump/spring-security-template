# JSON Web Tokens (JWT)

## 1. Token Types

Broadly speaking, there are two flavors of bearer tokens:

- **Opaque Tokens**
    - A random string with no intrinsic meaning.
    - Acts as a key into server‑side session or authorization data.
    - Every time you need to validate or inspect the token, you call back to the authorization
      server (often via an “introspection” endpoint).
    - Best suited for environments where a central authority handles all token checks.

- **JSON Web Tokens (JWTs)**
    - A self‑contained token carrying its own claims (user ID, roles, expiry, etc.).
    - Comprised of three Base64URL‑encoded segments joined by dots:
        1. **Header** (token type & signing algorithm)
        2. **Payload** (claims set)
        3. **Signature** (verifies issuer and integrity)
    - Can be validated locally by verifying the signature with a secret (HMAC) or public key (
      RSA/ECDSA), eliminating the need for a network round‑trip.

---

## 2. Anatomy of a JWT

### 1. Encoded Text

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiYWRtaW4iOnRydWV9
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### 2. Header (HMAC SHA‑256)

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### 3. Payload (Claims)

```json
{
  "sub": "1234567890",
  "name": "Alice",
  "admin": true,
  "iat": 1516239022
}
```

### 4. Signature

```text
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secretKey
)
```

---

## 3. General JWT Workflow in Spring Security

- User Authentication
    * Client submits credentials (e.g. via /login).
    * Spring Security verifies them against your user store.
- Token Issuance
    * On success, the server generates a JWT containing standard (e.g. sub, exp) and any custom
      claims.
    * The JWT is signed and returned to the client (often in an Authorization: Bearer <token>
      header).
- Token Usage
    * For each subsequent request, the client includes the JWT in the Authorization header.
- Token Validation
    * The server (e.g. via a filter or interceptor; see `JWTTokenGeneratorFilter` and
      `JWTTokenValidatorFilter`) extracts and verifies the JWT’s signature and expiry.
    * If valid, it builds an Authentication object (with user details and roles) and places it into
      the security context.