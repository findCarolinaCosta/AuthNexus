package com.AuthNexus.oauth2.service.oauth;

import com.AuthNexus.oauth2.repository.ClientRepository;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;

@Service
public class JPAUserDetailsService implements UserDetailsService {

  private final ClientRepository clientRepository;

  public JPAUserDetailsService(ClientRepository clientRepository) {
    this.clientRepository = clientRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    final var user = clientRepository.findByClientId(email)
        .orElseThrow(()-> new UsernameNotFoundException(email));

    final var simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_" + user.getType());

    return new User(
        user.getEmail(),
        user.getPassword(),
        List.of(simpleGrantedAuthority)
    );
  }

}
