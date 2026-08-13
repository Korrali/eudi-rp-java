package com.korrali.eudirp.spring;

import com.korrali.eudirp.cert.HotReloadingCertificateResolver;
import com.korrali.eudirp.cert.TrustListProvider;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Registers {@link EudiRpHealthIndicator} only when Spring Boot Actuator is actually on the
 * classpath — {@code spring-boot-actuator} is an optional dependency of this starter, not a
 * required one.
 */
@AutoConfiguration(after = EudiRpAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
public class EudiRpHealthAutoConfiguration {

    @Bean(name = "eudiRpHealthIndicator")
    @ConditionalOnMissingBean
    public EudiRpHealthIndicator eudiRpHealthIndicator(HotReloadingCertificateResolver eudiRpCertificateResolver,
                                                         TrustListProvider eudiRpTrustListProvider) {
        return new EudiRpHealthIndicator(eudiRpCertificateResolver, eudiRpTrustListProvider);
    }
}
