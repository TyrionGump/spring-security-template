package org.bugmakers404.spring.security.template.service;


import lombok.RequiredArgsConstructor;
import org.bugmakers404.spring.security.template.dao.UserInDBDAO;
import org.bugmakers404.spring.security.template.model.UserInDB;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


/**
 * {@link UserDetailsService} implementation that loads user data from the application’s store and
 * supplies it to {@link AuthenticationProvider} (e.g. {@link DaoAuthenticationProvider}).
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsServiceImpl implements UserDetailsService {

  private final UserInDBDAO userInDBDAO;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserInDB userInDB = userInDBDAO.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException(
            String.format("User cannot be found: username = %s", username)));

    UserBuilder userBuilder = User.builder();
    userBuilder.username(userInDB.getUsername())
        .password(userInDB.getPassword())
        // We add "ROLE_" in front because Spring’s default setup only recognizes roles that start
        // with that exact text. If you leave it off, checks like hasRole("USER") won’t work.
        // For details see `AuthorityAuthorizationManager`
        .authorities(new SimpleGrantedAuthority("ROLE_" + userInDB.getRole().name()));

    return userBuilder.build();

  }
}
