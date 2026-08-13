package com.korrali.eudirp.presentation;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Computes an OpenID4VP {@code x509_hash} Client Identifier: {@code x509_hash:<base64url SHA-256
 * of the DER-encoded leaf certificate>}. This is the scheme ARF Annex 2.03 (AS-WP-06-003) mandates
 * for RP authentication — not {@code x509_san_dns} — see DESIGN.md §2.1.
 */
public final class X509HashClientId {

    private static final String PREFIX = "x509_hash:";

    private X509HashClientId() {
    }

    public static String compute(X509Certificate leaf) throws CertificateEncodingException {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded());
            return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is a required JDK algorithm", e);
        }
    }
}
