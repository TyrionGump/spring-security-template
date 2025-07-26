package org.bugmakers404.spring.security.template.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A servlet filter that validates JSON Web Tokens (JWT) on incoming requests.
 * <p>
 * Placed immediately before {@link BasicAuthenticationFilter}, this filter executes for every
 * request whose servlet path is not “/generate_jwt_token”. It extracts the JWT from the
 * “Authorization” header, verifies its signature and expiration using the configured secret key,
 * and constructs an authenticated {@link UsernamePasswordAuthenticationToken} containing the user’s
 * name and roles, which is stored in the SecurityContext.
 * </p>
 * <p>
 * Requests bearing a valid token can proceed without additional database-backed authentication.
 * Tokens are issued by {@link JWTTokenGeneratorFilter}. See {@link SecurityFilterConfig} for filter
 * ordering and registration.
 * </p>
 */
@Slf4j
public class JWTTokenValidatorFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {

    String jwt = request.getHeader("JWT_Authorization");

    if (jwt != null) {
      try {
        Environment env = getEnvironment();
        String jwtSecret = env.getProperty("JWT_SECRET",
            "$2a$10$VVlYlP4xwSivh0KDMM7qqO5e4iPf4efMxaZJhd2.WAt1PMzrV/aim");
        SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        Claims payload = Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(jwt)
            .getPayload();

        String username = String.valueOf(payload.get("username"));
        String role = String.valueOf(payload.get("role"));

        // The constructor sets `authenticated` as true. This means that this request has completed authentication.
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            username, null, AuthorityUtils.commaSeparatedStringToAuthorityList(role));
        SecurityContextHolder.getContext().setAuthentication(authentication);
      } catch (Exception e) {
        throw new BadCredentialsException("Invalid JWT token");
      }
    }

    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return request.getServletPath().equals("/generate_jwt_token");
  }
}
