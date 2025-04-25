package org.bugmakers404.tools.controller;

import org.bugmakers404.tools.config.SecurityFilterConfig;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FilterController {

  /**
   * The access of this endpoint is managed by {@code defaultSecurityFilterChain} in {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/default")
  public String defaultSpringSecurityConfig() {
    return "default";
  }

  /**
   * The access of this endpoint is managed by {@code noSecurityFilterChain} in {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/noAuth")
  public String noAuth() {
    return "noAuth";
  }

  /**
   * The access of this endpoint is managed by {@code defaultFormLogin} in {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/defaultFormLogin")
  public String defaultFormLogin() {
    return "defaultFormLogin";
  }

  /**
   * The access of this endpoint is managed by {@code httpBasicLogin} in {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/httpBasicLogin")
  public String httpBasicLogin() {
    return "/httpBasicLogin";
  }
}
