package org.bugmakers404.tools.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class UserManagementConfig {

//  @Bean
//  UserDetailsService inMemoryUserDetailsManager() {
//    UserDetails user = User.withUsername("user").password("12345").authorities("read").build();
//    UserDetails admin = User.withUsername("admin").password("12345").authorities("admin").build();
//    return new InMemoryUserDetailsManager(user, admin);
//  }

  @Bean
  PasswordEncoder passwordEncoder() {
    // The default hashing algorithm is bcrypt
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
