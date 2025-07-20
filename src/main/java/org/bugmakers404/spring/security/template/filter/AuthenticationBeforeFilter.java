package org.bugmakers404.spring.security.template.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

/**
 * This a simple filter which is expected to be executed before {@link BasicAuthenticationFilter}.
 * Configure it in the {@code defaultSecurityFilterChain} of
 * {@link org.bugmakers404.spring.security.template.config.SecurityFilterConfig}.
 */
@Slf4j
public class AuthenticationBeforeFilter implements Filter {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String header = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);

    if (header != null) {
      header = header.trim();

      if (StringUtils.startsWithIgnoreCase(header, "Basic ")) {
        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded;

        try {
          decoded = Base64.getDecoder().decode(base64Token);
          String token = new String(decoded, StandardCharsets.UTF_8);
          int delimiter = token.indexOf(":"); // username:password

          if (delimiter == -1) {
            throw new IllegalArgumentException("Invalid basic authentication token");
          }

          String username = token.substring(0, delimiter);
          log.info("User is trying to log in: Username = {}", username);
        } catch (IllegalArgumentException e) {
          throw new ServletException("failed to decode basic authentication token", e);
        }
      }
    }

    // Always continue with the next filter in the chain:
    chain.doFilter(request, response);
  }
}
