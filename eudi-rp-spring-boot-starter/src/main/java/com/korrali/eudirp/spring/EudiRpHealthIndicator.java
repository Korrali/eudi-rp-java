package com.korrali.eudirp.spring;

import com.korrali.eudirp.cert.CertificateValidationException;
import com.korrali.eudirp.cert.HotReloadingCertificateResolver;
import com.korrali.eudirp.cert.RpKeyMaterial;
import com.korrali.eudirp.cert.TrustListProvider;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

/**
 * Reports the RP's own certificate validity and trust list freshness under
 * {@code /actuator/health/eudiRp} — exactly what an operator needs to know is fine without reading
 * logs: is the access certificate currently valid, and how stale is the trust list.
 */
public class EudiRpHealthIndicator implements HealthIndicator {

    private final HotReloadingCertificateResolver certificateResolver;
    private final TrustListProvider trustListProvider;

    public EudiRpHealthIndicator(HotReloadingCertificateResolver certificateResolver, TrustListProvider trustListProvider) {
        this.certificateResolver = certificateResolver;
        this.trustListProvider = trustListProvider;
    }

    @Override
    public Health health() {
        Health.Builder builder;
        try {
            RpKeyMaterial material = certificateResolver.resolveValid();
            builder = Health.up()
                    .withDetail("certificateSubject", material.leaf().getSubjectX500Principal().getName())
                    .withDetail("certificateNotAfter", material.leaf().getNotAfter().toInstant().toString());
        } catch (CertificateValidationException e) {
            builder = Health.down()
                    .withDetail("certificateError", e.getClass().getSimpleName())
                    .withDetail("certificateErrorMessage", e.getMessage());
        } catch (com.korrali.eudirp.cert.CertificateLoadException e) {
            builder = Health.down()
                    .withDetail("certificateError", "CertificateLoadException")
                    .withDetail("certificateErrorMessage", e.getMessage());
        }

        return builder
                .withDetail("trustListLastRefreshed", trustListProvider.lastRefreshed().toString())
                .withDetail("trustAnchorCount", trustListProvider.trustAnchors().size())
                .build();
    }
}
