package org.bugmakers404.spring.security.template.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A servlet filter that issues a JSON Web Token (JWT) for authenticated requests.
 * <p>
 * Placed immediately after {@link BasicAuthenticationFilter}, this filter listens for requests to
 * the “/generate_jwt_token” endpoint. Once a request is successfully authenticated, it assembles a
 * JWT containing the user’s name and roles, signs it with the configured secret key, and returns it
 * in the “Authorization” response header.
 * </p>
 * <p>
 * Clients can include this token in subsequent requests to bypass database-backed authentication:
 * those requests will be validated by {@link JWTTokenValidatorFilter}. See
 * {@link SecurityFilterConfig} for filter ordering and registration.
 * </p>
 */
@Slf4j
public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (authentication != null) {
      Environment env = getEnvironment();
      String jwtSecret = env.getProperty("JWT_SECRET",
          "$2a$10$VVlYlP4xwSivh0KDMM7qqO5e4iPf4efMxaZJhd2.WAt1PMzrV/aim");
      SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
      String jwt = Jwts.builder()
          .issuer("Bugmakers404 Org") // Who issue this token
          .subject("Bugmakers404 JWT Token")
          .claim("username", authentication.getName())
          .claim("role", authentication.getAuthorities().stream().map(
              GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
          .issuedAt(new Date())
          .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 8))
          .signWith(secretKey)
          .compact();

      response.setHeader("JWT_Authorization", jwt);
    }

    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !request.getServletPath().equals("/generate_jwt_token");
  }
}
