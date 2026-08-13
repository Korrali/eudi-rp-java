package com.korrali.eudirp.cert;

import com.korrali.eudirp.cert.support.StaticRevocationChecker;
import com.korrali.eudirp.cert.support.StaticTrustListProvider;
import com.korrali.eudirp.cert.support.TestCertificates;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * This is the "certificate rotated mid-session" scenario the demo's failure simulator shows live:
 * an operator swaps the on-disk keystore for a freshly-rotated certificate while the process is
 * still running with the old one cached in memory. The next request must not simply fail — it
 * should detect the stale/invalid certificate, reload from disk, and succeed on retry.
 */
class HotReloadingCertificateResolverTest {

    @Test
    void reloadsFromDiskAndSucceedsOnRetryWhenTheCachedCertificateHasExpired(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CA");
        Instant now = Instant.now();
        char[] password = "changeit".toCharArray();
        Path keystorePath = tempDir.resolve("rp.p12");

        TestCertificates.IssuedCertificate expiredLeaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(60, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS));
        TestCertificates.writePkcs12(keystorePath, password, "rp", expiredLeaf, ca.certificate());

        KeystoreCertificateSource source = new KeystoreCertificateSource(
                keystorePath, KeystoreType.PKCS12, password, "rp", password);
        RpCertificateStore store = new DefaultRpCertificateStore(source);
        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()),
                StaticRevocationChecker.alwaysGood(RevocationSource.CRL));
        HotReloadingCertificateResolver resolver = new HotReloadingCertificateResolver(store, validator);

        // The certificate on disk is still the expired one — resolving should fail even after retry.
        assertThatThrownBy(resolver::resolveValid).isInstanceOf(ExpiredCertificateException.class);

        // Now simulate an operator rotating the certificate: overwrite the keystore file in place.
        TestCertificates.IssuedCertificate freshLeaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));
        TestCertificates.writePkcs12(keystorePath, password, "rp", freshLeaf, ca.certificate());

        // The store's cache still holds the expired cert, but resolveValid() must detect the
        // validation failure, reload from the (now-rotated) source, and succeed on retry.
        RpKeyMaterial resolved = resolver.resolveValid();

        assertThat(resolved.leaf().getSerialNumber()).isEqualTo(freshLeaf.certificate().getSerialNumber());
    }

    @Test
    void doesNotReloadWhenTheCurrentCertificateIsAlreadyValid(@TempDir Path tempDir) throws Exception {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test CA");
        Instant now = Instant.now();
        char[] password = "changeit".toCharArray();
        Path keystorePath = tempDir.resolve("rp.p12");

        TestCertificates.IssuedCertificate validLeaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));
        TestCertificates.writePkcs12(keystorePath, password, "rp", validLeaf, ca.certificate());

        KeystoreCertificateSource source = new KeystoreCertificateSource(
                keystorePath, KeystoreType.PKCS12, password, "rp", password);
        RpCertificateStore store = new DefaultRpCertificateStore(source);
        CertificateValidator validator = new DefaultCertificateValidator(
                new StaticTrustListProvider(ca.certificate()),
                StaticRevocationChecker.alwaysGood(RevocationSource.CRL));
        HotReloadingCertificateResolver resolver = new HotReloadingCertificateResolver(store, validator);

        RpKeyMaterial resolved = resolver.resolveValid();

        assertThat(resolved.leaf().getSerialNumber()).isEqualTo(validLeaf.certificate().getSerialNumber());
    }
}
