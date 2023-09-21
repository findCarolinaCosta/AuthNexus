package com.AuthNexus.oauth2.repository;

import com.AuthNexus.oauth2.model.Client;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, Long> {
  Optional<Client> findByClientId(String username);
}
