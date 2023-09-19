package com.AuthNexus.oauth2.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Data;

@Entity
@Table(name = "oauth2_registered_client")
@Data
public class Client {
  @Id private String id;
  private String clientId;
  private Instant clientIdIssuedAt;
  private String clientSecret;
  private Instant clientSecretExpiresAt;
  private String clientName;

  @Column(length = 1000)
  private String clientAuthenticationMethods;

  @Column(length = 1000)
  private String authorizationGrantTypes;

  @Column(length = 1000)
  private String redirectUris;

  @Column(length = 1000)
  private String postLogoutRedirectUris;

  @Column(length = 1000)
  private String scopes;

  @Column(length = 2000)
  private String clientSettings;

  @Column(length = 2000)
  private String tokenSettings;

  public String getType() {
    return authorizationGrantTypes;
  }

  public String getEmail() {
    return clientId;
  }

  public String getPassword() {
    return clientSecret;
  }

  public String getName() {
    return clientName;
  }
}
