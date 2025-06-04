package org.bugmakers404.spring.security.template.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Customize {@link AuthenticationSuccessHandler} and use it to override the default post-login
 * success behaviour in {@link SecurityFilterConfig}.
 */
@Component
@Slf4j
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException {
    log.info("Login successfully: Username = {}", authentication.getName());
    response.sendRedirect("/");
  }
}
