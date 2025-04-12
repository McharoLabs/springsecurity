package com.seranise.spring.security.springsecurity.exception;

public class InvalidTokenException extends RuntimeException{
    public InvalidTokenException(String message) {
        super(message);
    }
}
