package org.bugmakers404.tools.dao;

import java.util.Optional;
import org.bugmakers404.tools.model.UserInDB;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserInDBDAO extends CrudRepository<UserInDB, Long> {

  Optional<UserInDB> findByUsername(String username);
}
