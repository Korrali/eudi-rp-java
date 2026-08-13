package com.korrali.eudirp.cert;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Checks whether a certificate has been revoked. See DESIGN.md §4 — a narrow extension point;
 * only local, direct-lookup default implementations ({@link CrlRevocationChecker},
 * {@link OcspRevocationChecker}) ship in this library.
 */
public interface RevocationChecker {

    RevocationStatus check(X509Certificate cert, List<X509Certificate> chain) throws RevocationCheckException;
}
