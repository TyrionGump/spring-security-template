package org.bugmakers404.spring.security.template.model;

public enum UserRoles {
  ROLE_ADMIN,
  ROLE_USER;

  public String getStrippedRoleString() {
    return this.name().replace("ROLE_", "");
  }
}
