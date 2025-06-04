package org.bugmakers404.spring.security.template.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;

/**
 * Custom handler for access-denied (authorization) failures thrown in
 * {@link ExceptionTranslationFilter}
 * <p>
 * When a user is authenticated but lacks the required permissions, this class sends a 403 Forbidden
 * response.
 * <p>
 * Registered in the SecurityFilterChain via {@code http.exceptionHandling(...)} in
 * {@link SecurityFilterConfig}.
 */
public class CustomAccessDeniedException implements AccessDeniedHandler {

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      AccessDeniedException accessDeniedException) throws IOException {
    response.setHeader("error-reason", "Authorization failed");
    response.setStatus(HttpStatus.FORBIDDEN.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    String customizedMessage = "I's a customized error message of authorization failure";
    response.getWriter().write(customizedMessage);
  }
}
