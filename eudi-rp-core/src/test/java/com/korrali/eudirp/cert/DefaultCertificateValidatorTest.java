package com.korrali.eudirp.cert;

import com.korrali.eudirp.cert.support.StaticRevocationChecker;
import com.korrali.eudirp.cert.support.StaticTrustListProvider;
import com.korrali.eudirp.cert.support.TestCertificates;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultCertificateValidatorTest {

    private final TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test RP Access CA");

    @Test
    void acceptsAValidTrustedNonRevokedCertificate() {
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()),
                StaticRevocationChecker.alwaysGood(RevocationSource.CRL));

        assertThatCode(() -> validator.validate(leaf.certificate(), List.of(ca.certificate())))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsAnExpiredCertificateWithTheExactExpiryTimestamp() {
        Instant now = Instant.now();
        Instant notAfter = now.minus(1, ChronoUnit.DAYS);
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(30, ChronoUnit.DAYS), notAfter);

        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()),
                StaticRevocationChecker.alwaysGood(RevocationSource.CRL));

        assertThatThrownBy(() -> validator.validate(leaf.certificate(), List.of(ca.certificate())))
                .isInstanceOf(ExpiredCertificateException.class)
                .satisfies(e -> assertThat(((ExpiredCertificateException) e).expiredAt())
                        .isCloseTo(notAfter, org.assertj.core.api.Assertions.within(1, ChronoUnit.SECONDS)));
    }

    @Test
    void rejectsANotYetValidCertificate() {
        Instant now = Instant.now();
        Instant notBefore = now.plus(30, ChronoUnit.DAYS);
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", notBefore, now.plus(60, ChronoUnit.DAYS));

        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()),
                StaticRevocationChecker.alwaysGood(RevocationSource.CRL));

        assertThatThrownBy(() -> validator.validate(leaf.certificate(), List.of(ca.certificate())))
                .isInstanceOf(ExpiredCertificateException.class)
                .satisfies(e -> assertThat(((ExpiredCertificateException) e).expiredAt())
                        .isCloseTo(notBefore, org.assertj.core.api.Assertions.within(1, ChronoUnit.SECONDS)));
    }

    @Test
    void rejectsACertificateSignedByAnUntrustedCa() {
        TestCertificates.IssuedCertificate untrustedCa = TestCertificates.selfSignedCa("Untrusted CA");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                untrustedCa, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()), // does NOT include untrustedCa
                StaticRevocationChecker.alwaysGood(RevocationSource.CRL));

        assertThatThrownBy(() -> validator.validate(leaf.certificate(), List.of(untrustedCa.certificate())))
                .isInstanceOf(UntrustedCertificateException.class);
    }

    @Test
    void rejectsARevokedCertificateAndSurfacesTheSourceAndReason() {
        Instant now = Instant.now();
        Instant revokedAt = now.minus(2, ChronoUnit.DAYS);
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(30, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        RevocationStatus revoked = RevocationStatus.revoked(RevocationSource.OCSP, revokedAt, RevocationReason.KEY_COMPROMISE);
        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()),
                StaticRevocationChecker.alwaysReturning(revoked));

        assertThatThrownBy(() -> validator.validate(leaf.certificate(), List.of(ca.certificate())))
                .isInstanceOf(RevokedCertificateException.class)
                .satisfies(e -> {
                    RevokedCertificateException revokedEx = (RevokedCertificateException) e;
                    assertThat(revokedEx.source()).isEqualTo(RevocationSource.OCSP);
                    assertThat(revokedEx.reason()).contains(RevocationReason.KEY_COMPROMISE);
                    assertThat(revokedEx.revokedAt()).contains(revokedAt);
                });
    }

    @Test
    void failsClosedWhenRevocationCheckItselfCannotBeCompleted() {
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        RevocationChecker brokenChecker = (cert, chain) -> {
            throw new RevocationCheckException("responder unreachable");
        };
        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()), brokenChecker, true);

        assertThatThrownBy(() -> validator.validate(leaf.certificate(), List.of(ca.certificate())))
                .isInstanceOf(UntrustedCertificateException.class);
    }

    @Test
    void failsOpenWhenConfiguredToAndRevocationCheckCannotBeCompleted() {
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        RevocationChecker brokenChecker = (cert, chain) -> {
            throw new RevocationCheckException("responder unreachable");
        };
        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()), brokenChecker, false);

        assertThatCode(() -> validator.validate(leaf.certificate(), List.of(ca.certificate())))
                .doesNotThrowAnyException();
    }
}
