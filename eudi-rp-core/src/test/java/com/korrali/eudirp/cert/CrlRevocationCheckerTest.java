package com.korrali.eudirp.cert;

import com.korrali.eudirp.cert.support.TestCertificates;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509CRL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CrlRevocationCheckerTest {

    @Test
    void reportsGoodWhenSerialIsNotOnTheCrl(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CRL CA");
        Path crlFile = tempDir.resolve("test.crl");

        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS),
                crlFile.toUri().toString(), null);

        Files.write(crlFile, TestCertificates.emptyCrl(ca).getEncoded());

        RevocationStatus status = new CrlRevocationChecker().check(leaf.certificate(), List.of(ca.certificate()));

        assertThat(status.revoked()).isFalse();
        assertThat(status.source()).isEqualTo(RevocationSource.CRL);
    }

    @Test
    void reportsRevokedWithReasonWhenSerialIsOnTheCrl(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CRL CA");
        Path crlFile = tempDir.resolve("test.crl");

        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS),
                crlFile.toUri().toString(), null);

        Instant revokedAt = now.minus(1, ChronoUnit.HOURS);
        X509CRL crl = TestCertificates.crl(ca, List.of(
                TestCertificates.RevokedEntry.of(leaf.certificate(), revokedAt)));
        Files.write(crlFile, crl.getEncoded());

        RevocationStatus status = new CrlRevocationChecker().check(leaf.certificate(), List.of(ca.certificate()));

        assertThat(status.revoked()).isTrue();
        assertThat(status.source()).isEqualTo(RevocationSource.CRL);
        assertThat(status.reason()).contains(RevocationReason.KEY_COMPROMISE);
        assertThat(status.revokedAt()).isPresent();
    }

    @Test
    void throwsWhenCertificateHasNoCrlDistributionPoint() {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CRL CA");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                        new CrlRevocationChecker().check(leaf.certificate(), List.of(ca.certificate())))
                .isInstanceOf(RevocationCheckException.class);
    }
}
