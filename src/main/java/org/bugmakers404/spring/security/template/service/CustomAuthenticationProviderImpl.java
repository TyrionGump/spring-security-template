package org.bugmakers404.spring.security.template.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Custom {@link AuthenticationProvider} for {@link ProviderManager} that authenticates credentials
 * by delegating to the injected UserDetailsService and PasswordEncoder.
 */
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProviderImpl implements AuthenticationProvider {

  private final UserDetailsService userDetailsService;

  private final PasswordEncoder passwordEncoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String pwd = authentication.getCredentials().toString();
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    if (passwordEncoder.matches(pwd, userDetails.getPassword())) {
      // Here, we can add extra validations based on your requirements
      return new UsernamePasswordAuthenticationToken(username, pwd, userDetails.getAuthorities());
    } else {
      throw new BadCredentialsException("Invalid password");
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
  }
}
