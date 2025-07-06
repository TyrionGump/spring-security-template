package org.bugmakers404.spring.security.template.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller that provides simple endpoints for the welcome page to verify role-based access.
 *
 * <p>The "/welcome" view (welcome.html) can invoke these endpoints to determine if the
 * authenticated user holds the required role.</p>
 *
 * <p>The authorization rules of these two endpoints are defined by the
 * {@code authorizationFilterChain} in
 * {@link org.bugmakers404.spring.security.template.config.SecurityFilterConfig}</p>
 */
@RestController
public class AuthorizationController {

  @GetMapping(value = "/admin_access")
  public String adminAccess() {
    return "You can access to this endpoint because you have admin access";
  }

  @GetMapping(value = "/user_access")
  public String userAccess() {
    return "You can access to this endpoint because you have user access";
  }
}
