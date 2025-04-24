package org.bugmakers404.tools.filter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityFilterConfig {

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
  @Order
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // Require authentication for all requests not matched by earlier filter chains
    // Explicitly set up the URLs. Otherwise, the default `AnyRequestMatcher.INSTANCE` pattern makes
    // the initialisation of this catch-all filter collide with others. Or, Set the @Order of
    // this bean as the last one.
    http.securityMatcher("/**")
        .authorizeHttpRequests(requests -> requests.anyRequest().authenticated());

    // Enable form-based login (renders a login HTML form at /login)
    http.formLogin(withDefaults());

    // Also support HTTP Basic authentication (e.g., for cURL or API clients)
    http.httpBasic(withDefaults());

    return http.build();
  }

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
  @Order(1) // Once a URL is first matched with a filter, others will be disregarded
  SecurityFilterChain noSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        // restrict this chain to URLs under /noAuth
        .securityMatcher("/noAuth/**", "/error")
        .authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
    return http.build();
  }

  /**
   * Handle the default form login by {@code UsernamePasswordAuthenticationFilter.attemptAuthentication}
   */
  @Bean
  @Order(1)
  SecurityFilterChain defaultFormLogin(HttpSecurity http) throws Exception {
    http.securityMatcher("/defaultFormLogin")
        .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
        .formLogin(withDefaults())
        .httpBasic(AbstractHttpConfigurer::disable);
    return http.build();
  }

  /**
   * Handle the http login by {@code BasicAuthenticationFilter.doFilterInternal}
   */
  @Bean
  @Order(1)
  SecurityFilterChain httpBasicLogin(HttpSecurity http) throws Exception {
    http.securityMatcher("/httpBasicLogin")
        .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
        .formLogin(FormLoginConfigurer::disable)
        .httpBasic(withDefaults());
    return http.build();
  }
}
