package org.bugmakers404.tools.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationEventListener {

  @EventListener
  public void onSuccess(AuthenticationSuccessEvent successEvent) {
    log.info("Succeeded to login: Username = {}", successEvent.getAuthentication().getName());
  }

  @EventListener
  public void onFailure(AbstractAuthenticationFailureEvent failureEvent) {
    log.error("Failed to login: Username = {}, Reason = \"{}\"",
        failureEvent.getAuthentication().getName(), failureEvent.getException().getMessage());
  }
}
