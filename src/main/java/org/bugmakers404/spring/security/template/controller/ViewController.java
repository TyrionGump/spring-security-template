package org.bugmakers404.spring.security.template.controller;

import org.bugmakers404.spring.security.template.config.WebConfig;
import org.bugmakers404.spring.security.template.handler.CustomAuthenticationSuccessHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Return the views defined under resources/templates.
 */
@Controller
public class ViewController {

  private static final Logger log = LoggerFactory.getLogger(ViewController.class);

  /**
   * Handle the login entry, and sequential redirect after log since by default
   *
   * @param error  By default, spring security redirects to /login?error via Get when an error
   *               occurs during login
   * @param logout By default, spring security redirects to /login?logout via Get after spring
   *               security receive a Post request via /logout
   */
  @GetMapping(path = "/login")
  public String login(@RequestParam(required = false) String error,
      @RequestParam(required = false) String logout, Model model) {

    if (error != null) {
      log.info("login error");
      model.addAttribute("loginError", true);
    }

    if (logout != null) {
      log.info("logout");
      model.addAttribute("logout", true);
    }
    return "login";
  }

  /**
   * Redirect target after successful login (configured in
   * {@link CustomAuthenticationSuccessHandler}).
   *
   * @param model          the model to populate view attributes
   * @param authentication the authenticated user (injected by Spring)
   * @return the "welcome" view name (configured in {@link WebConfig})
   */
  @GetMapping(path = "/")
  public String welcome(Model model, Authentication authentication) {
    if (authentication != null) {
      model.addAttribute("username", authentication.getName());
      model.addAttribute("roles", authentication.getAuthorities().toString());
    }
    return "welcome";
  }

  /**
   * Serves the same welcome page using SecurityContextHolder to obtain the authenticated user.
   *
   * @param model model the model to populate view attributes
   * @return the "welcome" view name (configured in {@link WebConfig})
   */
  @GetMapping(path = "/alternative")
  public String welcomeAlternative(Model model) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null) {
      model.addAttribute("username", authentication.getName());
      model.addAttribute("roles", authentication.getAuthorities().toString());
    }
    return "welcome";
  }
}
