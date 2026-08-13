package com.korrali.eudirp.cert;

/**
 * The revocation check itself could not be completed (responder unreachable, malformed CRL/OCSP
 * response, no revocation endpoint advertised) — distinct from a {@link RevokedCertificateException},
 * which means the check completed and found the certificate revoked.
 */
public final class RevocationCheckException extends Exception {

    public RevocationCheckException(String message, Throwable cause) {
        super(message, cause);
    }

    public RevocationCheckException(String message) {
        super(message);
    }
}
