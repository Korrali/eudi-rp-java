package com.korrali.eudirp.cert;

import java.time.Instant;
import java.util.Optional;

/**
 * Outcome of a single revocation check against one certificate.
 */
public record RevocationStatus(
        boolean revoked,
        RevocationSource source,
        Optional<Instant> revokedAt,
        Optional<RevocationReason> reason
) {

    public static RevocationStatus good(RevocationSource source) {
        return new RevocationStatus(false, source, Optional.empty(), Optional.empty());
    }

    public static RevocationStatus revoked(RevocationSource source, Instant revokedAt, RevocationReason reason) {
        return new RevocationStatus(true, source, Optional.of(revokedAt), Optional.of(reason));
    }
}
