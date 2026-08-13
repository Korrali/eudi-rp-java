package com.korrali.eudirp.spring;

import com.korrali.eudirp.cert.CertificateSource;
import com.korrali.eudirp.cert.CertificateValidator;
import com.korrali.eudirp.cert.CompositeRevocationChecker;
import com.korrali.eudirp.cert.DefaultCertificateValidator;
import com.korrali.eudirp.cert.DefaultRpCertificateStore;
import com.korrali.eudirp.cert.HotReloadingCertificateResolver;
import com.korrali.eudirp.cert.KeystoreCertificateSource;
import com.korrali.eudirp.cert.LocalFileTrustListProvider;
import com.korrali.eudirp.cert.RevocationChecker;
import com.korrali.eudirp.cert.RpCertificateStore;
import com.korrali.eudirp.cert.TrustListProvider;
import com.korrali.eudirp.presentation.LocalRegistrationMetadataProvider;
import com.korrali.eudirp.presentation.RegistrationMetadataProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configures a working relying party from {@link EudiRpProperties}. Every bean is
 * {@code @ConditionalOnMissingBean}: supplying your own {@link TrustListProvider},
 * {@link RevocationChecker}, or {@link RegistrationMetadataProvider} bean replaces the local-file
 * default — this is the Spring-idiomatic form of the provider-boundary extension points described
 * in DESIGN.md §4.
 */
@AutoConfiguration
@EnableConfigurationProperties(EudiRpProperties.class)
public class EudiRpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CertificateSource eudiRpCertificateSource(EudiRpProperties properties) {
        EudiRpProperties.Certificate cert = properties.getCertificate();
        return new KeystoreCertificateSource(
                cert.getKeystorePath(),
                cert.getKeystoreType(),
                cert.getStorePassword().toCharArray(),
                cert.getAlias(),
                (cert.getKeyPassword() != null ? cert.getKeyPassword() : cert.getStorePassword()).toCharArray());
    }

    @Bean
    @ConditionalOnMissingBean
    public RpCertificateStore eudiRpCertificateStore(CertificateSource eudiRpCertificateSource) {
        return new DefaultRpCertificateStore(eudiRpCertificateSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public TrustListProvider eudiRpTrustListProvider(EudiRpProperties properties) {
        return new LocalFileTrustListProvider(properties.getTrustList().getPath());
    }

    @Bean
    @ConditionalOnMissingBean
    public RevocationChecker eudiRpRevocationChecker() {
        return CompositeRevocationChecker.ocspThenCrl();
    }

    @Bean
    @ConditionalOnMissingBean
    public CertificateValidator eudiRpCertificateValidator(TrustListProvider eudiRpTrustListProvider,
                                                             RevocationChecker eudiRpRevocationChecker,
                                                             EudiRpProperties properties) {
        return new DefaultCertificateValidator(
                eudiRpTrustListProvider, eudiRpRevocationChecker, properties.getRevocation().isFailClosed());
    }

    @Bean
    @ConditionalOnMissingBean
    public HotReloadingCertificateResolver eudiRpCertificateResolver(RpCertificateStore eudiRpCertificateStore,
                                                                       CertificateValidator eudiRpCertificateValidator) {
        return new HotReloadingCertificateResolver(eudiRpCertificateStore, eudiRpCertificateValidator);
    }

    @Bean
    @ConditionalOnMissingBean
    public RegistrationMetadataProvider eudiRpRegistrationMetadataProvider(EudiRpProperties properties) {
        return new LocalRegistrationMetadataProvider(properties.getRegistration().getDeclaredAttributesFile());
    }
}
