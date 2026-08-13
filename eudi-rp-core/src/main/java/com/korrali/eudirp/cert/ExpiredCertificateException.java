package com.korrali.eudirp.cert;

import java.time.Instant;

/**
 * The certificate's validity period (notBefore/notAfter) does not cover the current time.
 * {@link #expiredAt()} is the boundary that was violated: {@code notAfter} for a certificate that
 * has expired, {@code notBefore} for one that isn't valid yet.
 */
public final class ExpiredCertificateException extends CertificateValidationException {

    private final Instant expiredAt;

    public ExpiredCertificateException(Instant expiredAt) {
        super("Certificate is not currently valid; validity boundary: " + expiredAt);
        this.expiredAt = expiredAt;
    }

    public Instant expiredAt() {
        return expiredAt;
    }
}
