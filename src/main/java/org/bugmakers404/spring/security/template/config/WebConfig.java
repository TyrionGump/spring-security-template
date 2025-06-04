package org.bugmakers404.spring.security.template.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

  @Override
  public void addViewControllers(ViewControllerRegistry registry) {
    // Here, it is not necessary to register login page if the url of login is the same as Spring Security's.
    registry.addViewController("/").setViewName("welcome");
    registry.addViewController("/alternative").setViewName("welcome");
  }

}
