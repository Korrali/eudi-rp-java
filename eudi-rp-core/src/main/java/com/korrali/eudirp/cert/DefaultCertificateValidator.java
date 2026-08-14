package com.korrali.eudirp.cert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
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

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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
            // BC's own X.509 CertificateFactory produces certificate objects whose .verify() uses
            // the BC provider internally, unlike the JDK's own X509CertImpl (produced by the
            // no-provider-arg CertificateFactory), which resolves its Signature engine via the
            // ambient global JCA provider order — Sun's ECDSA provider first, which doesn't
            // understand Brainpool curves. Re-encoding every certificate involved (chain AND trust
            // anchors — not just using the factory to wrap whatever concrete objects the caller
            // already handed us, since a factory can't retroactively change an existing object's
            // runtime type) sidesteps that without touching global JVM provider state or
            // hand-rolling PKIX path validation.
            CertificateFactory factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

            Set<TrustAnchor> anchors = new HashSet<>();
            for (X509Certificate anchor : trustListProvider.trustAnchors()) {
                anchors.add(new TrustAnchor(reencode(factory, anchor), null));
            }
            if (anchors.isEmpty()) {
                throw new UntrustedCertificateException("No trust anchors configured");
            }

            List<X509Certificate> fullChain = new ArrayList<>();
            fullChain.add(reencode(factory, leaf));
            for (X509Certificate cert : chain) {
                fullChain.add(reencode(factory, cert));
            }
            CertPath certPath = factory.generateCertPath(fullChain);

            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);

            // The JDK's default "PKIX" CertPathValidator (Sun's own implementation) verifies
            // signatures via the default JCA provider chain, which doesn't understand Brainpool
            // curves (RFC 5639) at all — verified empirically ("Curve not supported:
            // ECNamedCurveSpec"), even though BouncyCastle-generated Brainpool keys/certs are
            // otherwise perfectly valid. BC ships its own complete "PKIX" implementation that does
            // support them, so it's used explicitly rather than relying on whatever the default
            // provider happens to be — this is a general-purpose PKIX implementation, not a
            // Brainpool-specific shim, so NIST-curve and RSA chains validate through it identically.
            CertPathValidator validator = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
            validator.validate(certPath, params);
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException
                 | NoSuchAlgorithmException | NoSuchProviderException | CertificateException e) {
            throw new UntrustedCertificateException(
                    "Certificate chain does not build to a configured trust anchor: " + e.getMessage(), e);
        }
    }

    private static X509Certificate reencode(CertificateFactory factory, X509Certificate cert) throws CertificateException {
        try {
            return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(cert.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new CertificateException("Failed to re-encode certificate for BC-native chain validation", e);
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
