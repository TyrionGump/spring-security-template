package org.bugmakers404.tools.service;


import lombok.RequiredArgsConstructor;
import org.bugmakers404.tools.dao.UserInDBDAO;
import org.bugmakers404.tools.model.UserInDB;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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
        .authorities(userInDB.getRole());

    return userBuilder.build();

  }
}
