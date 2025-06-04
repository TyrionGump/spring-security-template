package org.bugmakers404.spring.security.template.dao;

import java.util.Optional;
import org.bugmakers404.spring.security.template.model.UserInDB;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserInDBDAO extends CrudRepository<UserInDB, Long> {

  Optional<UserInDB> findByUsername(String username);
}
