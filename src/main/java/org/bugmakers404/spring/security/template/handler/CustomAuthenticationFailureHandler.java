package org.bugmakers404.spring.security.template.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/**
 * Customize {@link AuthenticationFailureHandler} and use it to override the default post-login
 * failure behaviour in {@link SecurityFilterConfig}.
 */
@Component
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException {
    log.error("Failed to login: error = '{}'", exception.getMessage());
    response.sendRedirect("/login?error");
  }
}
