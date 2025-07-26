package org.bugmakers404.spring.security.template.controller;

import lombok.extern.slf4j.Slf4j;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class FilterController {

  /**
   * The access of this endpoint is managed by {@code defaultSecurityFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/default")
  public String defaultSpringSecurityConfig() {
    log.info("Hit the endpoint /default");
    return "default";
  }

  /**
   * The access of this endpoint is managed by {@code noSecurityFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/noAuth")
  public String noAuth() {
    log.info("Hit the endpoint /noAuth");
    return "noAuth";
  }

  /**
   * The access of this endpoint is managed by {@code noSecurityFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(path = "/invalid_session")
  public String sessionExpiry() {
    log.info("Hit the endpoint /invalid_session");
    return "The session ID is invalid. A potential reason is that the session has expired";
  }

  /**
   * This is expected to be hit by Postman to see how JWT token is generated or sent.
   */
  @GetMapping("/generate_jwt_token")
  public String jwtToken() {
    log.info("Hit the endpoint /generate_jwt_token");
    return "This is a JWT token endpoint. You can check the generated token in the response JWT_Authorization header. Then, you can use it to access the protected endpoint /default.";
  }
}
