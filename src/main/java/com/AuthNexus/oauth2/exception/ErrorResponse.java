package com.AuthNexus.oauth2.exception;

import lombok.Data;

@Data
public class ErrorResponse {

  private String timestamp;
  private int status;
  private String error;
  private String path;
}
