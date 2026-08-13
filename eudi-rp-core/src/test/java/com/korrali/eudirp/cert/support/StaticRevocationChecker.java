package com.korrali.eudirp.cert.support;

import com.korrali.eudirp.cert.RevocationChecker;
import com.korrali.eudirp.cert.RevocationCheckException;
import com.korrali.eudirp.cert.RevocationStatus;

import java.security.cert.X509Certificate;
import java.util.List;

/** A {@link RevocationChecker} stub that always returns a fixed, pre-set status — used to isolate
 * validator tests (expiry, chain-of-trust) from real CRL/OCSP infrastructure. */
public final class StaticRevocationChecker implements RevocationChecker {

    private final RevocationStatus status;

    private StaticRevocationChecker(RevocationStatus status) {
        this.status = status;
    }

    public static StaticRevocationChecker alwaysGood(com.korrali.eudirp.cert.RevocationSource source) {
        return new StaticRevocationChecker(RevocationStatus.good(source));
    }

    public static StaticRevocationChecker alwaysReturning(RevocationStatus status) {
        return new StaticRevocationChecker(status);
    }

    @Override
    public RevocationStatus check(X509Certificate cert, List<X509Certificate> chain) throws RevocationCheckException {
        return status;
    }
}
