package com.korrali.eudirp.cert;

/**
 * Base type for every way an RP access certificate can fail validation. Sealed so callers can
 * exhaustively switch over the concrete failure class instead of string-matching a message.
 */
public sealed class CertificateValidationException extends Exception
        permits ExpiredCertificateException, RevokedCertificateException,
                UntrustedCertificateException, MalformedCertificateException {

    CertificateValidationException(String message) {
        super(message);
    }

    CertificateValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
