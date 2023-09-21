package com.AuthNexus.oauth2.exception;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.stream.Collectors;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorViewResolver;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@ControllerAdvice
@RestController
@RequestMapping("/error")
public class ErrorHandlerController extends AbstractErrorController {

  public ErrorHandlerController(ErrorAttributes errorAttributes,
      ObjectProvider<ErrorViewResolver> errorViewResolvers) {
    super(errorAttributes,
        errorViewResolvers.orderedStream().collect(Collectors.toUnmodifiableList()));
  }

  @PostMapping
  public ResponseEntity<ErrorResponse> handleError(HttpServletRequest request) {
    Integer statusCode = (Integer) request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
    String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);

    if (statusCode == null) {
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR.value();
    }

    if (errorMessage == null) {
      errorMessage = HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase();
    }

    ErrorResponse errorResponse = new ErrorResponse();
    errorResponse.setTimestamp(LocalDateTime.now().toString());
    errorResponse.setStatus(statusCode);
    errorResponse.setError(errorMessage);
    errorResponse.setPath(request.getRequestURI());

    return ResponseEntity.status(statusCode).body(errorResponse);
  }

  @ExceptionHandler(Exception.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ResponseBody
  public void handleGenericException(Exception ex, HttpServletRequest request) {
    handleError(request);
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ErrorResponse> handleValidationExceptions(
      MethodArgumentNotValidException ex, HttpServletRequest request) {

    ErrorResponse errorResponse = new ErrorResponse();
    Integer statusCode = ex.getStatusCode().value();

    ex.getBindingResult().getAllErrors().forEach((error) -> {
      String errorMessage = error.getDefaultMessage();
      errorResponse.setError(errorMessage);
    });

    errorResponse.setTimestamp(LocalDateTime.now().toString());
    errorResponse.setStatus(statusCode);
    errorResponse.setPath(request.getRequestURI());

    return ResponseEntity.status(statusCode).body(errorResponse);
  }
}
