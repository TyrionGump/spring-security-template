package org.bugmakers404.tools.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.bugmakers404.tools.config.SecurityFilterConfig;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;

/**
 * Custom entry point for HTTP Basic authentication failures thrown in
 * {@link ExceptionTranslationFilter}
 * <p>
 * When authentication fails (e.g., missing or invalid credentials), this class sends a 401
 * Unauthorized response.
 * <p>
 * Plugged into the SecurityFilterChain via {@code http.httpBasic(...)} in
 * {@link SecurityFilterConfig}.
 */
public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException {
    response.setHeader("error-reason", "Authentication failed");
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    String customizedMessage = "I's a customized error message of authentication failure";
    response.getWriter().write(customizedMessage);
  }
}
