package org.bugmakers404.spring.security.template.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthorizationEventListener {

  @EventListener
  public void onFailure(AuthorizationDeniedEvent<?> deniedEvent) {
    log.error("Failed to login: Username = {}, Reason = \"{}\"",
        deniedEvent.getAuthentication().get().getName(),
        deniedEvent.getAuthorizationResult().toString());
  }
}
