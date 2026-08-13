package com.korrali.eudirp.cert;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Parses using the JDK's built-in {@code X.509} {@link CertificateFactory} — strict DER, the
 * default path. Rejects certificates that use BER constructs (e.g. indefinite-length encoding)
 * that some legacy sovereign-issuer CA software still emits.
 */
public final class StrictCertificateParser implements CertificateParser {

    @Override
    public X509Certificate parse(byte[] derEncoded) throws MalformedCertificateException {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(derEncoded));
        } catch (CertificateException | ClassCastException e) {
            throw new MalformedCertificateException(
                    "JDK strict X.509 parser rejected the certificate: " + e.getMessage(), false, e);
        }
    }
}
