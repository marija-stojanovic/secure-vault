package com.securevault.auth.oidc;

public class OidcLoginException extends RuntimeException {

    private final String code;

    public OidcLoginException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
