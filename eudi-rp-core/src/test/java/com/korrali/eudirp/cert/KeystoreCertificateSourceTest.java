package com.korrali.eudirp.cert;

import com.korrali.eudirp.cert.support.TestCertificates;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeystoreCertificateSourceTest {

    @Test
    void loadsKeyAndChainFromAPkcs12File(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CA");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        Path keystorePath = tempDir.resolve("rp.p12");
        char[] password = "changeit".toCharArray();
        TestCertificates.writePkcs12(keystorePath, password, "rp", leaf, ca.certificate());

        KeystoreCertificateSource source = new KeystoreCertificateSource(
                keystorePath, KeystoreType.PKCS12, password, "rp", password);

        RpKeyMaterial material = source.load();

        assertThat(material.leaf().getSubjectX500Principal())
                .isEqualTo(leaf.certificate().getSubjectX500Principal());
        assertThat(material.chain()).hasSize(1);
        assertThat(material.chain().get(0).getSubjectX500Principal())
                .isEqualTo(ca.certificate().getSubjectX500Principal());
        assertThat(material.privateKey()).isEqualTo(leaf.privateKey());
    }

    @Test
    void failsWithATypedExceptionWhenTheFileIsMissing(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("does-not-exist.p12");

        KeystoreCertificateSource source = new KeystoreCertificateSource(
                missing, KeystoreType.PKCS12, "x".toCharArray(), "rp", "x".toCharArray());

        assertThatThrownBy(source::load).isInstanceOf(CertificateLoadException.class);
    }

    @Test
    void failsWithATypedExceptionWhenTheAliasDoesNotExist(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CA");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));
        Path keystorePath = tempDir.resolve("rp.p12");
        char[] password = "changeit".toCharArray();
        TestCertificates.writePkcs12(keystorePath, password, "rp", leaf, ca.certificate());

        KeystoreCertificateSource source = new KeystoreCertificateSource(
                keystorePath, KeystoreType.PKCS12, password, "wrong-alias", password);

        assertThatThrownBy(source::load).isInstanceOf(CertificateLoadException.class);
    }
}
