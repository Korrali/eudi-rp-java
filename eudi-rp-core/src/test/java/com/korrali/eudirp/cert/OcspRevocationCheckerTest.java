package com.korrali.eudirp.cert;

import com.korrali.eudirp.cert.support.TestCertificates;
import com.korrali.eudirp.cert.support.TestOcspResponder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OcspRevocationCheckerTest {

    @Test
    void reportsGoodForASignedGoodResponse() throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test OCSP CA");
        try (TestOcspResponder responder = TestOcspResponder.startAlwaysReturning(ca, CertificateStatus.GOOD)) {
            Instant now = Instant.now();
            TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                    ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS),
                    null, responder.uri().toString());

            RevocationStatus status = new OcspRevocationChecker().check(leaf.certificate(), List.of(ca.certificate()));

            assertThat(status.revoked()).isFalse();
            assertThat(status.source()).isEqualTo(RevocationSource.OCSP);
        }
    }

    @Test
    void reportsRevokedForASignedRevokedResponse() throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test OCSP CA");
        Instant revokedAt = Instant.now().minus(3, ChronoUnit.HOURS);
        RevokedStatus revokedStatus = new RevokedStatus(Date.from(revokedAt), org.bouncycastle.asn1.x509.CRLReason.keyCompromise);

        try (TestOcspResponder responder = TestOcspResponder.startAlwaysReturning(ca, revokedStatus)) {
            Instant now = Instant.now();
            TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                    ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS),
                    null, responder.uri().toString());

            RevocationStatus status = new OcspRevocationChecker().check(leaf.certificate(), List.of(ca.certificate()));

            assertThat(status.revoked()).isTrue();
            assertThat(status.source()).isEqualTo(RevocationSource.OCSP);
            assertThat(status.reason()).contains(RevocationReason.KEY_COMPROMISE);
        }
    }

    @Test
    void throwsWhenCertificateHasNoOcspResponderConfigured() {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test OCSP CA");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        assertThatThrownBy(() -> new OcspRevocationChecker().check(leaf.certificate(), List.of(ca.certificate())))
                .isInstanceOf(RevocationCheckException.class);
    }
}
