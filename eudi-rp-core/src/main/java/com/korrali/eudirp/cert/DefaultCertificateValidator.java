package com.korrali.eudirp.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The default {@link CertificateValidator}: temporal validity, then PKIX chain-building against
 * {@link TrustListProvider}'s anchors (with the JDK's own revocation checking turned off — this
 * library does that separately via {@link RevocationChecker}), then revocation.
 *
 * <p>If the revocation check itself fails (responder unreachable, malformed response — as opposed
 * to completing and reporting the certificate revoked), the default policy is fail-closed: treat
 * an undeterminable revocation status as untrusted. Pass {@code failClosedOnRevocationCheckError =
 * false} to fail open instead — a deliberate risk-acceptance switch, not a default.
 */
public final class DefaultCertificateValidator implements CertificateValidator {

    private static final Logger log = LoggerFactory.getLogger(DefaultCertificateValidator.class);

    private final TrustListProvider trustListProvider;
    private final RevocationChecker revocationChecker;
    private final boolean failClosedOnRevocationCheckError;

    public DefaultCertificateValidator(TrustListProvider trustListProvider, RevocationChecker revocationChecker) {
        this(trustListProvider, revocationChecker, true);
    }

    public DefaultCertificateValidator(TrustListProvider trustListProvider, RevocationChecker revocationChecker,
                                        boolean failClosedOnRevocationCheckError) {
        this.trustListProvider = trustListProvider;
        this.revocationChecker = revocationChecker;
        this.failClosedOnRevocationCheckError = failClosedOnRevocationCheckError;
    }

    @Override
    public void validate(X509Certificate leaf, List<X509Certificate> chain) throws CertificateValidationException {
        checkTemporalValidity(leaf);
        checkChainOfTrust(leaf, chain);
        checkRevocation(leaf, chain);
    }

    private static void checkTemporalValidity(X509Certificate leaf) throws ExpiredCertificateException {
        try {
            leaf.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new ExpiredCertificateException(leaf.getNotAfter().toInstant());
        } catch (CertificateNotYetValidException e) {
            throw new ExpiredCertificateException(leaf.getNotBefore().toInstant());
        }
    }

    private void checkChainOfTrust(X509Certificate leaf, List<X509Certificate> chain) throws UntrustedCertificateException {
        try {
            Set<TrustAnchor> anchors = new HashSet<>();
            for (X509Certificate anchor : trustListProvider.trustAnchors()) {
                anchors.add(new TrustAnchor(anchor, null));
            }
            if (anchors.isEmpty()) {
                throw new UntrustedCertificateException("No trust anchors configured");
            }

            List<X509Certificate> fullChain = new ArrayList<>();
            fullChain.add(leaf);
            fullChain.addAll(chain);

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            CertPath certPath = factory.generateCertPath(fullChain);

            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException
                 | NoSuchAlgorithmException | CertificateException e) {
            throw new UntrustedCertificateException(
                    "Certificate chain does not build to a configured trust anchor: " + e.getMessage(), e);
        }
    }

    private void checkRevocation(X509Certificate leaf, List<X509Certificate> chain)
            throws RevokedCertificateException, UntrustedCertificateException {
        RevocationStatus status;
        try {
            status = revocationChecker.check(leaf, chain);
        } catch (RevocationCheckException e) {
            if (failClosedOnRevocationCheckError) {
                throw new UntrustedCertificateException(
                        "Revocation status could not be determined (fail-closed): " + e.getMessage(), e);
            }
            log.warn("Revocation check failed and fail-open is configured; treating as not revoked: {}", e.getMessage());
            return;
        }
        if (status.revoked()) {
            throw new RevokedCertificateException(status);
        }
    }
}
