package com.AuthNexus.oauth2.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
//import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@SpringBootTest
@AutoConfigureMockMvc
public class TokenTest {

  @Autowired
  private MockMvc mockMvc;

  @Test
  @DisplayName("Emission OAuth2 token")
  @WithMockUser(username = "user", password = "password", roles = "USER")
  public void testEmissionOAuth2() throws Exception {
    // Simulate a request to the OAuth2 token issuance endpoint
    mockMvc.perform(
          MockMvcRequestBuilders
            .post("/oauth")
            .param("grant_type", "password")
            .param("username", "usuariodoteste")
            .param("password", "senhadoteste")
            .param("client_id", "cliente")
            .param("client_secret", "senha")
        )
        .andExpect(MockMvcResultMatchers.status().isOk());
  }
}
