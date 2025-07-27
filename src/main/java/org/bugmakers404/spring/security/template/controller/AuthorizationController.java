package org.bugmakers404.spring.security.template.controller;

import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller that provides simple endpoints for the welcome page to verify role-based access.
 *
 * <p>The "/welcome" view (welcome.html) can invoke these endpoints to determine if the
 * authenticated user holds the required role.</p>
 */
@RestController
public class AuthorizationController {

  /**
   * The authorization rule of this endpoint is defined by the {@code authorizationFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(value = "/admin_access")
  public String adminAccess() {
    return "You can access to this endpoint because you have admin access";
  }

  /**
   * The authorization rule of this endpoint is defined by the {@code authorizationFilterChain} in
   * {@link SecurityFilterConfig}
   */
  @GetMapping(value = "/user_access")
  public String userAccess() {
    return "You can access to this endpoint because you have user access";
  }

  /**
   * To debug the process of @PreAuthorize, see {@link AuthorizationManagerBeforeMethodInterceptor}
   */
  @GetMapping(value = "/admin_method_access")
  @PreAuthorize("hasRole('ADMIN')") // Check authorization before invoking
  public String adminMethodAccess() {
    return "You can access to this method because you have admin access";
  }

  /**
   * To debug the process of @PostAuthorize, see {@link AuthorizationManagerAfterMethodInterceptor}
   */
  @GetMapping(value = "/user_method_access")
  @PostAuthorize("hasRole('USER')") // Check authorization before returning
  public String userMethodAccess() {
    return "You can access to this method because you have user access";
  }


}
