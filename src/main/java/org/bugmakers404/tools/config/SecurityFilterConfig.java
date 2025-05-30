package org.bugmakers404.tools.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.bugmakers404.tools.exception.CustomAccessDeniedException;
import org.bugmakers404.tools.exception.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityFilterConfig {

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
        // However, user registration requires post requests.
        .csrf(CsrfConfigurer::disable)
        .securityMatcher("/noAuth", "/error", "/register", "/invalid_session")
        .authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
    return http.build();
  }

  /**
   * Catch-all security filter chain for any request not handled by more specific chains.
   *
   * <p>Ensures that all remaining endpoints require authentication and provides both
   * form-based and HTTP Basic login mechanisms.</p>
   *
   * <p><strong>Configuration details:</strong>
   * <ul>
   *   <li>{@code authorizeHttpRequests(auth -> auth.anyRequest().authenticated())}
   *       – Require a logged-in user for every URL.</li>
   *   <li>{@code formLogin(withDefaults())}
   *       – Enable the default Spring Security login form at {@code /login}.</li>
   *   <li>{@code httpBasic(withDefaults())}
   *       – Support HTTP Basic authentication for API clients and non-browser callers.</li>
   * </ul>
   * </p>
   */
  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // Require authentication for all requests not matched by earlier filter chains
    // Explicitly set up the URLs. Otherwise, the default `AnyRequestMatcher.INSTANCE` pattern makes
    // the initialisation of this catch-all filter collide with others. Or, Set the @Order of
    // this bean as the last one.
    http.securityMatcher("/**")
        .csrf(CsrfConfigurer::disable)
        .authorizeHttpRequests(requests -> requests.anyRequest().authenticated());

    // Enable form-based login (renders a login HTML form at /login)
    // Handle the default form login by `UsernamePasswordAuthenticationFilter.attemptAuthentication`
    http.formLogin(withDefaults());

    // Also support HTTP Basic authentication (e.g., for cURL or API clients)
    // Handle the http login by `BasicAuthenticationFilter.doFilterInternal`
    http.httpBasic(
        // We override the default `AuthenticationEntryPoint` to throw our own exception
        // and return a custom response on authentication failure.
        httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.authenticationEntryPoint(
            new CustomBasicAuthenticationEntryPoint()));

    http.exceptionHandling(
        // We override the default ·AccessDeniedHandler to throw our own exception and return a
        // custom response on authorization failure.
        httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(
            new CustomAccessDeniedException()));

    // For invalid session id, including session expiry, redirect users to a specific url.
    http.sessionManagement(
        httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.invalidSessionUrl(
            "/invalid_session").maximumSessions(3).maxSessionsPreventsLogin(true));

    // Session Fixation Attack
    // An attacker first acquires a valid session ID before the user authenticates. They then lure
    // the victim into using that same ID (for example, localhost:8080?sessionId=123456).
    // Because the server issues a session ID on initial access—regardless of login status—the victim’s
    // subsequent login binds their credentials to the attacker’s pre-set session.
    // The attacker, knowing this session ID, can then reuse it to hijack the victim’s authenticated session.
    http.sessionManagement(
        httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionFixation()
            .changeSessionId());

    return http.build();
  }
}
