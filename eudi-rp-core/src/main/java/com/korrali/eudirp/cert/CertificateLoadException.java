package com.korrali.eudirp.cert;

/**
 * The keystore itself could not be read (missing file, wrong password, no such alias) — distinct
 * from {@link CertificateValidationException}, which covers a keystore that loaded fine but whose
 * certificate fails validation.
 */
public final class CertificateLoadException extends Exception {

    public CertificateLoadException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateLoadException(String message) {
        super(message);
    }
}
