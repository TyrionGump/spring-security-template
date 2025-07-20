package org.bugmakers404.spring.security.template.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.NonNull;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * This lets browser-based clients get the latest asked or raw token automatically—without calling a
 * dedicated `/csrf` endpoint-simply by inspecting the response header.
 * <p>
 * For the filter order configuration, please refer to {@code corsAndCsrfFilterChain} in
 * {@link SecurityFilterConfig}.
 */
public class CsrfTokenResponseHeaderBindingFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain chain)
      throws ServletException, IOException {
    CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    if (token != null) {
      response.setHeader("X-CSRF-TOKEN", token.getToken());
    }

    // Always continue with the next filter in the chain:
    chain.doFilter(request, response);
  }
}
