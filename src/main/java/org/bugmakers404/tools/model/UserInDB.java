package org.bugmakers404.tools.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;


@Data
@Entity
@Table(name = "mock_user")
@RequiredArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED) // Only used for JPA reflection
public class UserInDB {

  @Id
  // Hibernate discard the manually assigned IDs before poking with the DB
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NonNull
  private String username;

  @NonNull
  private String password;

  @NonNull
  private String email;

  @NonNull
  private String role;
}
