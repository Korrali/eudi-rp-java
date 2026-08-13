package com.korrali.eudirp.cert;

/**
 * The certificate bytes could not be parsed into an {@link java.security.cert.X509Certificate}.
 *
 * <p>Raised either after the strict (JDK) parse path failed and the tolerant (BouncyCastle) path
 * also failed — {@link #tolerantParsePathEngaged()} is {@code true} in that case — or, in principle,
 * before any tolerant path was attempted. In practice {@link ToleratingCertificateParser} always
 * attempts both paths before giving up, so this exception normally means both failed.
 */
public final class MalformedCertificateException extends CertificateValidationException {

    private final boolean tolerantParsePathEngaged;

    public MalformedCertificateException(String message, boolean tolerantParsePathEngaged, Throwable cause) {
        super(message, cause);
        this.tolerantParsePathEngaged = tolerantParsePathEngaged;
    }

    /** Whether the BouncyCastle fallback path was attempted (and, since this exception was
     * thrown, also failed). {@code false} means the strict path failed and no fallback was
     * available or configured. */
    public boolean tolerantParsePathEngaged() {
        return tolerantParsePathEngaged;
    }
}
