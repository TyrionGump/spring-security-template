package org.bugmakers404.spring.security.template.controller;

import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FilterController {

  /**
   * The access of this endpoint is managed by {@code defaultSecurityFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/default")
  public String defaultSpringSecurityConfig() {
    return "default";
  }

  /**
   * The access of this endpoint is managed by {@code noSecurityFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/noAuth")
  public String noAuth() {
    return "noAuth";
  }

  /**
   * The access of this endpoint is managed by {@code noSecurityFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/invalid_session")
  public String sessionExpiry() {
    return "The session ID is invalid. A potential reason is that the session has expired";
  }
}
