package com.AuthNexus.oauth2.config;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@Validated
@ConfigurationProperties("aw.auth")
@Data
public class AuthProperties {

  @NotBlank
  private String providerUri;

  @NotNull
  private JksProperties jks;

  @Data
  static class JksProperties {

    @NotBlank
    private String keypass;

    @NotBlank
    private String storepass;

    @NotBlank
    private String alias;

    @NotBlank
    private String path;
  }
}
