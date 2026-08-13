package com.korrali.eudirp.cert;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Validates a leaf certificate and its chain: temporal validity, chain-of-trust to a
 * {@link TrustListProvider} anchor, and revocation status via a {@link RevocationChecker}. Throws
 * one of the four {@link CertificateValidationException} subtypes on failure — never a generic
 * exception — so callers can branch on failure class.
 */
public interface CertificateValidator {

    void validate(X509Certificate leaf, List<X509Certificate> chain) throws CertificateValidationException;
}
