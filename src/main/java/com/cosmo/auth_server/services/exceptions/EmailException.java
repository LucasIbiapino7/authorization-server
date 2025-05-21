package com.cosmo.auth_server.services.exceptions;

public class EmailException extends RuntimeException{
    public EmailException(String message) {
        super(message);
    }
}
