package org.bugmakers404.tools;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    /**
     * A default filter provided by SpringBootWebSecurityConfiguration.
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // All requests should be authorized before hitting endpoints.
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        // By default, form submissions use PUT method with content-type application/x-www-form-urlencoded,
        // serializing fields as username=alice&password=secret in the body
        http.formLogin(withDefaults());
        // General HTTP methods send payloads like {"username":"alice","password":"secret"}
        // with content type application/json
        http.httpBasic(withDefaults());
        return http.build();
    }
}
