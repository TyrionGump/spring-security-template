package org.bugmakers404.spring.security.template.controller;

import lombok.RequiredArgsConstructor;
import org.bugmakers404.spring.security.template.dao.UserInDBDAO;
import org.bugmakers404.spring.security.template.model.UserInDB;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserManagementController {

  private final UserInDBDAO userInDBDAO;

  private final PasswordEncoder passwordEncoder;

  @PostMapping(path = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> register(@RequestBody UserInDB user) {
    String hashedPwd = passwordEncoder.encode(user.getPassword());
    user.setPassword(hashedPwd);
    try {
      userInDBDAO.save(user);
      return ResponseEntity.status(HttpStatus.CREATED)
          .body("Given user is successfully registered.");
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body("An exception occurred: " + e.getMessage());
    }
  }
}
