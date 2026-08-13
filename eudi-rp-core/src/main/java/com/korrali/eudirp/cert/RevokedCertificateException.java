package com.korrali.eudirp.cert;

import java.time.Instant;
import java.util.Optional;

/** The certificate was found revoked by a CRL or OCSP check. */
public final class RevokedCertificateException extends CertificateValidationException {

    private final RevocationSource source;
    private final Optional<Instant> revokedAt;
    private final Optional<RevocationReason> reason;

    public RevokedCertificateException(RevocationStatus status) {
        super("Certificate revoked (source=" + status.source()
                + ", reason=" + status.reason().map(Enum::name).orElse("unspecified") + ")");
        if (!status.revoked()) {
            throw new IllegalArgumentException("RevokedCertificateException requires a revoked RevocationStatus");
        }
        this.source = status.source();
        this.revokedAt = status.revokedAt();
        this.reason = status.reason();
    }

    /** Which mechanism caught the revocation. */
    public RevocationSource source() {
        return source;
    }

    public Optional<Instant> revokedAt() {
        return revokedAt;
    }

    public Optional<RevocationReason> reason() {
        return reason;
    }
}
