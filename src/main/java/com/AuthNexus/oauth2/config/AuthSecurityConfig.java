package com.AuthNexus.oauth2.config;

import com.AuthNexus.oauth2.model.Client;
import com.AuthNexus.oauth2.repository.ClientRepository;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.time.Duration;

@EnableWebSecurity
@Configuration
public class AuthSecurityConfig {

  @Value("${spring.profiles.active}")
  private String activeProfile;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.formLogin(Customizer.withDefaults())
        .logout(logout -> logout.logoutSuccessUrl("/login").invalidateHttpSession(true));

    return http.build();
  }

  @Bean
  public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception {

    http.csrf(AbstractHttpConfigurer::disable)
        .authorizeRequests(
            authorize ->
                authorize.requestMatchers("/health").permitAll().anyRequest().authenticated())
        .formLogin(Customizer.withDefaults())
        .logout(logout -> logout.logoutSuccessUrl("/login").invalidateHttpSession(true));

    return http.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository(
      PasswordEncoder passwordEncoder, JdbcTemplate jdbcTemplate) {
    JdbcRegisteredClientRepository clientRepository =
        new JdbcRegisteredClientRepository(jdbcTemplate);

    if ("dev".equals(activeProfile)) {

      if (clientRepository.findByClientId("awuser") == null) {
        RegisteredClient awuserClient =
            RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("awuser")
                .clientSecret(passwordEncoder.encode("1234567"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("users:read")
                .scope("users:write")
                .tokenSettings(
                    TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        clientRepository.save(awuserClient);
      }

      if (clientRepository.findByClientId("awblog") == null) {
        RegisteredClient awblogClient =
            RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("awblog")
                .clientSecret(passwordEncoder.encode("123456"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/authorized")
                .redirectUri("https://oidcdebugger.com/debug")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope("myuser:read")
                .scope("myuser:write")
                .scope("posts:write")
                .tokenSettings(
                    TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        clientRepository.save(awblogClient);
      }
    }

    return clientRepository;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  @Bean
  public OAuth2AuthorizationService auth2AuthorizationService(
      JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
    // detalhes do usuário no contexto de autorização no servidor
    return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
  }

  @Bean
  public AuthorizationServerSettings providerSettings(AuthProperties authProperties) {
    AuthorizationServerSettings authorizationServerSettings =
        AuthorizationServerSettings.builder()
            .issuer(
                authProperties.getProviderUri()) // configuração do emission (issuer) no token JWT
            .build();

    return authorizationServerSettings;
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtEncodingContextOAuth2TokenCustomizer(
      ClientRepository userRepository) {
    return (context -> {
      Authentication authentication = context.getPrincipal();
      if (authentication.getPrincipal() instanceof User) {
        final User user = (User) authentication.getPrincipal();

        final Client userEntity = userRepository.findByClientId(user.getUsername()).orElseThrow();

        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : user.getAuthorities()) {
          authorities.add(authority.toString());
        }
        context.getClaims().claim("user_id", userEntity.getId().toString());
        context.getClaims().claim("user_fullname", userEntity.getName());
        context.getClaims().claim("authorities", authorities);
      }
    });
  }
}
