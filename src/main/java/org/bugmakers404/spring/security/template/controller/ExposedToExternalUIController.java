package org.bugmakers404.spring.security.template.controller;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.bugmakers404.spring.security.template.config.SecurityFilterConfig;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes test endpoints for CORS and CSRF flows to the mock UI at "cors/mock_UI.html". The access
 * to these paths is managed by {@code corsAndCsrfFilterChain} in {@link SecurityFilterConfig}.
 */
@Slf4j
@RestController
public class ExposedToExternalUIController {

  @GetMapping(path = "/cors", produces = MediaType.APPLICATION_JSON_VALUE)
  public Map<String, String> getMockInfo() {
    log.info("Hit the endpoint /cors");
    Map<String, String> resp = new HashMap<>();
    resp.put("status", "ok");
    resp.put("message", "CORS endpoint reached with get method.");
    return resp;
  }

  @GetMapping("/csrf")
  public CsrfToken getCSRFToken(CsrfToken token) {
    return token;
  }

  @PostMapping(path = "/csrf", produces = MediaType.APPLICATION_JSON_VALUE)
  public Map<String, String> updateMockInfo(HttpServletRequest request) {
    // They are the same thing. "_csrf" is the default request attribtue name defined in
    // {@link CsrfTokenRequestAttributeHandler}
    log.info("The csrf token is {}", request.getAttribute(CsrfToken.class.getName()));
    log.info("The csrf token is {}", request.getAttribute("_csrf"));

    log.info("Hit the endpoint /csrf");
    Map<String, String> resp = new HashMap<>();
    resp.put("status", "ok");
    resp.put("message", "CSRF endpoint reached with post method.");
    return resp;
  }
}
