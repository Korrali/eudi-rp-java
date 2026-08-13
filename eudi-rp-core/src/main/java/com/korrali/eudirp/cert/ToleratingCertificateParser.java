package com.korrali.eudirp.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

/**
 * The parser this library actually wires up by default: try {@link StrictCertificateParser}
 * first, and only if that fails, fall back to {@link TolerantCertificateParser}. Logs a warning
 * when the fallback engages, since a cert needing the tolerant path is a signal worth an operator
 * seeing, even though the request itself proceeds.
 */
public final class ToleratingCertificateParser implements CertificateParser {

    private static final Logger log = LoggerFactory.getLogger(ToleratingCertificateParser.class);

    private final CertificateParser strict;
    private final CertificateParser tolerant;

    public ToleratingCertificateParser() {
        this(new StrictCertificateParser(), new TolerantCertificateParser());
    }

    public ToleratingCertificateParser(CertificateParser strict, CertificateParser tolerant) {
        this.strict = strict;
        this.tolerant = tolerant;
    }

    @Override
    public X509Certificate parse(byte[] derEncoded) throws MalformedCertificateException {
        try {
            return strict.parse(derEncoded);
        } catch (MalformedCertificateException strictFailure) {
            log.warn("Strict X.509 parse failed ({}); engaging tolerant BouncyCastle fallback",
                    strictFailure.getMessage());
            try {
                X509Certificate certificate = tolerant.parse(derEncoded);
                log.warn("Tolerant parse path succeeded where the strict path failed");
                return certificate;
            } catch (MalformedCertificateException tolerantFailure) {
                MalformedCertificateException combined = new MalformedCertificateException(
                        "Both strict and tolerant parsers rejected the certificate. Strict: "
                                + strictFailure.getMessage() + ". Tolerant: " + tolerantFailure.getMessage(),
                        true, tolerantFailure);
                combined.addSuppressed(strictFailure);
                throw combined;
            }
        }
    }
}
