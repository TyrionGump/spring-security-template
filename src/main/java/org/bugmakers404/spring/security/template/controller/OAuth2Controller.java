package org.bugmakers404.spring.security.template.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class OAuth2Controller {

  /**
   * Test the different login results via the default Spring Security login form and OAuth2
   * provider.
   */
  @GetMapping("/oauth2")
  public String oauth2(Authentication authentication) {
    if (authentication instanceof UsernamePasswordAuthenticationToken) {
      return "You logged in via username/password form";
    } else if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
      return "You logged in via OAuth2 provider: %s".formatted(
          oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());
    }
    return "You are not logged in";
  }
}
