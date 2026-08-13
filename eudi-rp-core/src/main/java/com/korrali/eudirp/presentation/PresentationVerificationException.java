package com.korrali.eudirp.presentation;

/** The wallet's authorization response failed verification against the original request. */
public final class PresentationVerificationException extends Exception {

    public PresentationVerificationException(String message) {
        super(message);
    }

    public PresentationVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
