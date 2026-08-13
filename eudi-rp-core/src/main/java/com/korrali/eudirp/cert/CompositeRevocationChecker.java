package com.korrali.eudirp.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Tries OCSP first (cheaper, near-real-time), falling back to CRL if the OCSP check itself fails
 * (responder unreachable, no AIA extension, malformed response) — not if OCSP succeeds and reports
 * good, since that's a real answer, not a failure. Either checker finding the certificate revoked
 * is authoritative and returned immediately without consulting the other.
 */
public final class CompositeRevocationChecker implements RevocationChecker {

    private static final Logger log = LoggerFactory.getLogger(CompositeRevocationChecker.class);

    private final RevocationChecker ocsp;
    private final RevocationChecker crl;

    public CompositeRevocationChecker(RevocationChecker ocsp, RevocationChecker crl) {
        this.ocsp = ocsp;
        this.crl = crl;
    }

    public static CompositeRevocationChecker ocspThenCrl() {
        return new CompositeRevocationChecker(new OcspRevocationChecker(), new CrlRevocationChecker());
    }

    @Override
    public RevocationStatus check(X509Certificate cert, List<X509Certificate> chain) throws RevocationCheckException {
        try {
            return ocsp.check(cert, chain);
        } catch (RevocationCheckException ocspFailure) {
            log.warn("OCSP check failed ({}); falling back to CRL", ocspFailure.getMessage());
            try {
                return crl.check(cert, chain);
            } catch (RevocationCheckException crlFailure) {
                RevocationCheckException combined = new RevocationCheckException(
                        "Both OCSP and CRL checks failed. OCSP: " + ocspFailure.getMessage()
                                + ". CRL: " + crlFailure.getMessage(), crlFailure);
                combined.addSuppressed(ocspFailure);
                throw combined;
            }
        }
    }
}
