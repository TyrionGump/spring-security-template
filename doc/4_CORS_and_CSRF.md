# CORS and CSRF

## Cross-Origin Resource Sharing (CORS)

For the concept of CORS, please refer
to [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS).

### Browser-Enforced Origin Check

When JavaScript in a web page makes a cross-origin request, the browser:

1. Automatically attaches an Origin header indicating the page’s origin.
2. After receiving the response, looks for `Access-Control-Allow-Origin:<origin>` (or `*`) in the
   headers.
3. If the header matches or is wildcard-permissive, the browser exposes the body to JavaScript;
   otherwise, it blocks access—even though the HTTP response completed successfully at the network
   level.
4. This enforcement is part of the Same-Origin Policy defined by browsers—not the server—ensuring
   malicious frontends cannot stealthily read data

### Spring Security’s CorsFilter Integration

In a Spring Boot application secured by Spring Security:

1. Calling `http.cors()` registers a CorsFilter at the start of the security filter chain, so CORS
   logic runs before authentication or authorization filters
2. Spring delegates to the `DefaultCorsProcessor` to validate the incoming `Origin` header against
   your configured `allowedOrigins`.
    - If allowed, it adds `Access-Control-Allow-Origin` (and related) headers to the outgoing
      response.
    - If disallowed, it rejects the request immediately with 403 Forbidden and no response body.
      Spring Security’s early rejection simply prevents disallowed origins from ever reaching
      controllers, but it does not perform any extra authentication or authorization beyond the
      origin check

## Cross-Site Request Forgery (CSRF)

For the concept of CSRF, please refer
to [MDN CSRF](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF)

### Example

- Imagine you’re logged into your bank website in one tab.
- In another tab, you open a malicious site that secretly submits a “send money” request to your
  bank.
- Because your browser includes your bank’s login cookie automatically, the bank thinks it’s a
  legitimate request from you.

### Why does It Work?

- Browsers attach cookies or basic auth headers to all requests by default—including those triggered
  by hidden forms or images.
- The server sees valid credentials and processes the action, even though you never meant to do it.

### Solution Options in Spring Security

Spring Security provides several built-in ways to handle CSRF protection:

1. `HttpSessionCsrfTokenRepository`: Stores the CSRF token in the user’s HTTP session and expects it
   back in a request parameter or header.
2. `CookieCsrfTokenRepository`: Issues the CSRF token in a readable cookie (often named
   `XSRF-TOKEN`) and requires the client to send it in a custom header on each state-changing
   request.

### Simple Explanation: Cookie-Based CSRF Protection

Here, we use `CookieCsrfTokenRepository` as an example:

1. When the user authenticates, Spring Security’s `CookieCsrfTokenRepository` generates a random
   token and sets it in a `non-HttpOnly` cookie named (by default) `XSRF-TOKEN`
2. Your JavaScript reads the `XSRF-TOKEN` cookie and includes its value in an `X-XSRF-TOKEN` request
   header on every POST/PUT/DELETE call.
3. On each incoming request, Spring Security compares the header token against the cookie value it
   originally issued. If they match, the request proceeds; if not, it’s rejected with HTTP 403.

The exact token type (masked or raw), the header it’s sent in, and the mechanisms for transmitting,
resolving, and validating that token all depend on your CSRF handler configuration. See the
corsAndCsrfFilterChain definition in your SecurityFilterConfig class for the precise setup.


