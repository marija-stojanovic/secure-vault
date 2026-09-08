package com.securevault.auth.api;

import com.securevault.auth.AuthException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Clock;
import java.time.Instant;

@RestControllerAdvice
public class ApiExceptionHandler {

    private final Clock clock;

    public ApiExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(AuthException.class)
    ResponseEntity<ApiErrorResponse> handleAuthException(AuthException exception) {
        return ResponseEntity.status(exception.getStatus()).body(new ApiErrorResponse(
                Instant.now(clock),
                exception.getStatus().value(),
                exception.getMessage()
        ));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiErrorResponse> handleValidationException() {
        return ResponseEntity.badRequest().body(new ApiErrorResponse(
                Instant.now(clock),
                400,
                "Zahtjev sadrži neispravne podatke"
        ));
    }
}
