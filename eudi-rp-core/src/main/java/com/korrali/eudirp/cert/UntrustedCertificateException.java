package com.korrali.eudirp.cert;

/**
 * The certificate chain does not build to a trust anchor supplied by the configured
 * {@link TrustListProvider}, or the chain signature itself does not verify.
 */
public final class UntrustedCertificateException extends CertificateValidationException {

    public UntrustedCertificateException(String message) {
        super(message);
    }

    public UntrustedCertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
