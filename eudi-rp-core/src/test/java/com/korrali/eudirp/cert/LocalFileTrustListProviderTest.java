package com.korrali.eudirp.cert;

import com.korrali.eudirp.cert.support.TestCertificates;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class LocalFileTrustListProviderTest {

    @Test
    void loadsTrustAnchorsFromASinglePemBundleFile(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CA");
        Path bundle = tempDir.resolve("trust.pem");
        Files.writeString(bundle, toPem(ca.certificate()));

        LocalFileTrustListProvider provider = new LocalFileTrustListProvider(bundle);

        assertThat(provider.trustAnchors()).hasSize(1);
        assertThat(provider.trustAnchors().get(0).getSubjectX500Principal())
                .isEqualTo(ca.certificate().getSubjectX500Principal());
    }

    @Test
    void loadsTrustAnchorsFromEveryPemFileInADirectory(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca1 = TestCertificates.selfSignedCa("CA One");
        TestCertificates.IssuedCertificate ca2 = TestCertificates.selfSignedCa("CA Two");
        Files.writeString(tempDir.resolve("ca1.pem"), toPem(ca1.certificate()));
        Files.writeString(tempDir.resolve("ca2.pem"), toPem(ca2.certificate()));
        Files.writeString(tempDir.resolve("ignored.txt"), "not a cert");

        LocalFileTrustListProvider provider = new LocalFileTrustListProvider(tempDir);

        assertThat(provider.trustAnchors()).hasSize(2);
    }

    @Test
    void reloadPicksUpChangesOnDisk(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca1 = TestCertificates.selfSignedCa("CA One");
        Path bundle = tempDir.resolve("trust.pem");
        Files.writeString(bundle, toPem(ca1.certificate()));
        LocalFileTrustListProvider provider = new LocalFileTrustListProvider(bundle);
        assertThat(provider.trustAnchors()).hasSize(1);

        TestCertificates.IssuedCertificate ca2 = TestCertificates.selfSignedCa("CA Two");
        Files.writeString(bundle, toPem(ca1.certificate()) + toPem(ca2.certificate()));
        Instant beforeReload = provider.lastRefreshed();
        provider.reload();

        assertThat(provider.trustAnchors()).hasSize(2);
        assertThat(provider.lastRefreshed()).isAfterOrEqualTo(beforeReload);
    }

    private static String toPem(X509Certificate cert) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }
}
