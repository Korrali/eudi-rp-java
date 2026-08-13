package com.korrali.eudirp.spring;

import com.korrali.eudirp.cert.CertificateValidator;
import com.korrali.eudirp.cert.HotReloadingCertificateResolver;
import com.korrali.eudirp.cert.RevocationChecker;
import com.korrali.eudirp.cert.RpCertificateStore;
import com.korrali.eudirp.cert.TrustListProvider;
import com.korrali.eudirp.presentation.RegistrationMetadataProvider;
import com.korrali.eudirp.spring.support.MinimalTestPki;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the exact "under twenty lines of application config" claim from DESIGN.md/the project
 * brief: the four properties below are the whole config surface a caller needs to get a working
 * relying party out of the starter.
 */
class EudiRpAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EudiRpAutoConfiguration.class, EudiRpHealthAutoConfiguration.class));

    @Test
    void wiresAWorkingRelyingPartyFromMinimalConfig(@TempDir Path tempDir) throws Exception {
        MinimalTestPki.Setup pki = MinimalTestPki.writeCaSignedLeafKeystore(tempDir);
        Path declaredAttributesFile = tempDir.resolve("declared-attributes.txt");
        Files.writeString(declaredAttributesFile, "given_name\nfamily_name\n");

        contextRunner
                .withPropertyValues(
                        "eudirp.certificate.keystore-path=" + pki.keystorePath(),
                        "eudirp.certificate.store-password=" + new String(pki.password()),
                        "eudirp.certificate.alias=" + pki.alias(),
                        "eudirp.trust-list.path=" + pki.trustAnchorPath(),
                        "eudirp.registration.declared-attributes-file=" + declaredAttributesFile,
                        // MinimalTestPki's leaf certificate carries no CRLDP/AIA extensions (a
                        // test-fixture simplification — a real access certificate would), so with
                        // the default fail-closed policy neither OCSP nor CRL can be attempted and
                        // health would correctly report DOWN. Not part of the "<20 lines" minimal
                        // config claim for a real deployment; here purely to test the wiring.
                        "eudirp.revocation.fail-closed=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(RpCertificateStore.class);
                    assertThat(context).hasSingleBean(TrustListProvider.class);
                    assertThat(context).hasSingleBean(RevocationChecker.class);
                    assertThat(context).hasSingleBean(CertificateValidator.class);
                    assertThat(context).hasSingleBean(HotReloadingCertificateResolver.class);
                    assertThat(context).hasSingleBean(RegistrationMetadataProvider.class);
                    assertThat(context).hasSingleBean(EudiRpHealthIndicator.class);

                    EudiRpHealthIndicator healthIndicator = context.getBean(EudiRpHealthIndicator.class);
                    Health health = healthIndicator.health();
                    assertThat(health.getStatus().getCode()).isEqualTo("UP");
                    assertThat(health.getDetails()).containsKey("certificateNotAfter");
                    assertThat(health.getDetails()).containsKey("trustAnchorCount");
                });
    }

    @Test
    void aUserSuppliedTrustListProviderBeanReplacesTheLocalFileDefault(@TempDir Path tempDir) throws Exception {
        MinimalTestPki.Setup pki = MinimalTestPki.writeCaSignedLeafKeystore(tempDir);
        Path declaredAttributesFile = tempDir.resolve("declared-attributes.txt");
        Files.writeString(declaredAttributesFile, "given_name\n");

        contextRunner
                .withUserConfiguration(CustomTrustListProviderConfig.class)
                .withPropertyValues(
                        "eudirp.certificate.keystore-path=" + pki.keystorePath(),
                        "eudirp.certificate.store-password=" + new String(pki.password()),
                        "eudirp.certificate.alias=" + pki.alias(),
                        "eudirp.trust-list.path=" + pki.trustAnchorPath(),
                        "eudirp.registration.declared-attributes-file=" + declaredAttributesFile)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(TrustListProvider.class)).isSameAs(CustomTrustListProviderConfig.INSTANCE);
                });
    }

    @org.springframework.context.annotation.Configuration
    static class CustomTrustListProviderConfig {
        static final TrustListProvider INSTANCE = new TrustListProvider() {
            @Override
            public java.util.List<java.security.cert.X509Certificate> trustAnchors() {
                return java.util.List.of();
            }

            @Override
            public java.time.Instant lastRefreshed() {
                return java.time.Instant.EPOCH;
            }
        };

        @org.springframework.context.annotation.Bean
        TrustListProvider eudiRpTrustListProvider() {
            return INSTANCE;
        }
    }
}
