package org.bugmakers404.spring.security.template.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class UserManagementConfig {

  /**
   * If you create your own {@link UserDetailsService} bean, there is no need to manually define a
   * bean for {@link AuthenticationProvider}, because by default a {@link DaoAuthenticationProvider}
   * bean will be automatically created for us, which will automatically pick up your defined
   * {@link UserDetailsService} bean. However, if you define 2 or more {@link UserDetailsService}
   * beans, then you need to define your own {@link AuthenticationProvider}.
   */
//  @Bean
//  UserDetailsService inMemoryUserDetailsManager() {
//
//    UserDetails inMemoryUser = User.withUsername("inMemory").password("12345").authorities("admin").build();
//    return new InMemoryUserDetailsManager(inMemoryUser);
//  }

  @Bean
  PasswordEncoder passwordEncoder() {
    // The default hashing algorithm is bcrypt
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
