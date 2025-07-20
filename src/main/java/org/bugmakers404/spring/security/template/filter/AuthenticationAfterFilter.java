package org.bugmakers404.spring.security.template.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * This a simple filter which is expected to be executed after {@link BasicAuthenticationFilter}.
 * Configure it in the {@code defaultSecurityFilterChain} of
 * {@link org.bugmakers404.spring.security.template.config.SecurityFilterConfig}.
 */
@Slf4j
public class AuthenticationAfterFilter implements Filter {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (authentication != null) {
      log.info("User is logged in: Username = {}", authentication.getName());
    }

    // Always continue with the next filter in the chain:
    chain.doFilter(request, response);
  }
}
