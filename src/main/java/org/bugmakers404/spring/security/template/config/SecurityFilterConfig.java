package org.bugmakers404.spring.security.template.config;

import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.bugmakers404.spring.security.template.exception.CustomAccessDeniedHandler;
import org.bugmakers404.spring.security.template.exception.CustomBasicAuthenticationEntryPoint;
import org.bugmakers404.spring.security.template.filter.CsrfTokenResponseHeaderBindingFilter;
import org.bugmakers404.spring.security.template.handler.CustomAuthenticationFailureHandler;
import org.bugmakers404.spring.security.template.handler.CustomAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
public class SecurityFilterConfig {

  private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

  private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

  /**
   * Defines a security filter chain that only applies to requests under "/noAuth/**".
   *
   * <p>
   * Use {@code securityMatcher("/noAuth/**")} to scope this entire chain to those URLs, and use
   * {@code authorizeHttpRequests(requests -> requests.anyRequest().permitAll())} to permit all
   * requests once the chain is selected.
   * </p>
   *
   * <p><strong>Why this matters:</strong>
   * <ul>
   *   <li>{@code securityMatcher} controls <em>which URLs</em> this filter chain handles.</li>
   *   <li>{@code requestMatchers} (inside {@code authorizeHttpRequests}) controls
   *       <em>what authorization rules</em> apply <em>within</em> that chain.</li>
   * </ul>
   * Simply permitting "/noAuth/**" with {@code requestMatchers} alone won’t stop the chain
   * from matching every request—it only affects authorization, not chain selection.
   * </p>
   */
  @Bean
  @Order(1)
  // Once a URL is first matched with a filter, others will be disregarded
  SecurityFilterChain noSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        // By default, csrf can allow get requests.
        // However, user registration requires post-requests.
        .securityMatcher("/noAuth", "/error", "/register", "/invalid_session")
        .authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
    return http.build();
  }

  /**
   * Configures a security filter chain that handles Cross-Origin Resource Sharing (CORS) and
   * Cross-Site Request Forgery (CSRF) configurations. This filter chain permits all requests to
   * "/cors" and "/csrf" endpoints, enforces CORS policies, and provides CSRF protection using a
   * cookie-stored token mechanism.
   * <p>
   * For the config implementation details, refer to {@link CsrfFilter},
   * {@link CookieCsrfTokenRepository}, {@link CsrfTokenRequestAttributeHandler},
   * {@link XorCsrfTokenRequestAttributeHandler}.
   */
  @Bean
  @Order(1)
  SecurityFilterChain corsAndCsrfFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/cors", "/csrf")
        .authorizeHttpRequests(requests -> requests.anyRequest().permitAll());

    // CORS: browser-enforced policy for cross-origin resource sharing.
    // - Simple requests (GET, HEAD, POST with safe headers) are sent directly.
    // - Other methods (PUT, DELETE, etc.) trigger an OPTIONS preflight.
    http.cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfigurationSource()));

    // CSRF protection tokens are used only on unsafe, state-changing methods (POST, PUT, DELETE, PATCH)
    // and are not applied to safe methods like GET, HEAD, or OPTIONS
    http.csrf(csrfConfigurer -> csrfConfigurer
        // `CookieCsrfTokenRepository` delays the generation of csrf token until the user
        // really needs it and the csrf token is sent back to store in the browser's cookies named "XSRF-TOKEN".
        // Therefore, If we use `CsrfTokenRequestAttributeHandler`, on the UI page "{project_root}/cors/mock_ui.html",
        // - First click on "Update Data (POST /csrf)" issues a POST without any CSRF token → blocked.
        // - After the 403, the server sets the raw token cookie.
        // - Second click auto-sends cookie, so the POST now succeeds.

        // Also, the token is not stored in the repository. Instead, it stores in the cookie. The cookie repository retrieves the token
        // from the cookie, and it might be kind of confusing.
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        // Default: XorCsrfTokenRequestAttributeHandler
        // - Masks the raw token on EVERY response with fresh randomness when the token is `get` since the get of token is deferred.
        // - Embeds the random mask + masked bytes in one Base64 payload
        // - UI must read and send back the masked token in the header

        // Alternative: CsrfTokenRequestAttributeHandler
        // - Simply exposes the raw token as an attribute. This means that you can change the cookie value in the browser since
        //   it only cares about if the token in the request's cookie is equal to the token in the request's header.
        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()));

    // Usually, this should add after `BasicAuthenticationFilter.class`
    http.addFilterAfter(new CsrfTokenResponseHeaderBindingFilter(), CsrfFilter.class);

    return http.build();
  }

  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
    configuration.setAllowedMethods(Collections.singletonList("*"));
    configuration.setAllowedHeaders(Collections.singletonList("*"));
    // Browser requires concrete origin with allowCredentials=true, wildcard '*' not allowed
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L);
    return request -> configuration;
  }


  /**
   * Catch-all security filter chain for any request not handled by more specific chains.
   *
   * <p>Ensures that all remaining endpoints require authentication and provides both
   * form-based and HTTP Basic login mechanisms.</p>
   */
  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // Require authentication for all requests not matched by earlier filter chains
    // Explicitly set up the URLs. Otherwise, the default `AnyRequestMatcher.INSTANCE` pattern makes
    // the initialisation of this catch-all filter collide with others. Or, Set the @Order of
    // this bean as the last one.
    http.securityMatcher("/**").csrf(CsrfConfigurer::disable);

    // Rules are evaluated in order; Spring Security stops at the first matching rule.
    http.authorizeHttpRequests(requests -> requests.requestMatchers("/login/**", "/logout")
        .permitAll()
        .anyRequest()
        .authenticated());

    // Enable form-based login (renders a login HTML form at /login)
    // `UsernamePasswordAuthenticationFilter.attemptAuthentication` handles form submission.
    http.formLogin(form -> form
        // Custom login entry URL (default value is "/login")
        .loginPage("/login")
        // Redirect here if no saved request exists; otherwise redirect to the originally requested protected URL.
        .defaultSuccessUrl("/default")
        // Define the parameter names of the post-request provided by the login form
        .usernameParameter("username")
        .passwordParameter("password")
        // Customize redirect url on login failure (default value is "/login?error")
        .failureUrl("/login?error")
        // Custom handlers override default behaviours (e.g. SavedRequestAwareAuthenticationSuccessHandler).
        // Ensure your custom handlers perform their own redirects. For example,
        // `.defaultSuccessUrl` is overridden by the `sendRedirect` in `CustomAuthenticationSuccessHandler`.
        // Therefore, remember to set the redirect url in the custom handler
        .successHandler(customAuthenticationSuccessHandler)
        .failureHandler(customAuthenticationFailureHandler));

    http.logout(logoutConfigurer -> logoutConfigurer
            // Customize redirect url on logout (default value is "/login?logout")
            .logoutSuccessUrl("/login?logout")
            // Invalidate the HTTP session (clears any session attributes)
            .invalidateHttpSession(true)
            // Clear SecurityContext to prevent any in‐flight request from accidentally restoring credentials.
            .clearAuthentication(true)
            // Remove the JSESSIONID cookie in the browser; otherwise, the browser keeps sending the old session ID
            .deleteCookies("JSESSIONID")

        // When you call logout, Spring Security invalidates the session on the server, but the browser may still hold the old JSESSIONID cookie.
        // Because the browser appears “in a session” (via the stale cookie) even though it’s been invalidated server-side,
        // any request carrying that cookie triggers the `invalidSessionUrl` redirect (if configured under http.sessionManagement).

        // To avoid confusing behaviour—such as seeing the “invalid session” page instead of /login?logout—ensure:
        //   1. The JSESSIONID cookie is deleted immediately after logout.
        //   2. Your invalidSessionUrl strategy aligns with the logout flow so that stale cookies don’t cause unexpected redirects.
    );

    // Also support HTTP Basic authentication (e.g., for cURL or API clients)
    // Handle the http login by `BasicAuthenticationFilter.doFilterInternal`
    http.httpBasic(
        // We override the default `AuthenticationEntryPoint` to throw our own exception
        // and return a custom response on authentication failure.
        httpBasicConfigurer -> httpBasicConfigurer.authenticationEntryPoint(
            new CustomBasicAuthenticationEntryPoint()));

    http.exceptionHandling(
        // We override the default ·AccessDeniedHandler to throw our own exception and return a
        // custom response on authorization failure.
        exceptionHandlingConfigurer -> exceptionHandlingConfigurer.accessDeniedHandler(
            new CustomAccessDeniedHandler()));

    // For invalid session id, including session expiry, redirect users to a specific url.
    http.sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer
        // Redirect any request carrying invalid session info.
        .invalidSessionUrl("/invalid_session").maximumSessions(10).maxSessionsPreventsLogin(true));

    // Session Fixation Attack
    // An attacker first acquires a valid session ID before the user authenticates. They then lure
    // the victim into using that same ID (for example, localhost:8080?sessionId=123456).
    // Because the server issues a session ID on initial access—regardless of login status—the victim’s
    // later login binds their credentials to the attacker’s pre-set session.
    // The attacker, knowing this session ID, can then reuse it to hijack the victim’s authenticated session.
    http.sessionManagement(
        sessionManagementConfigurer -> sessionManagementConfigurer.sessionFixation()
            .changeSessionId());

    return http.build();
  }
}
