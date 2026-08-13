package com.korrali.eudirp.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves the RP's own key material, validating it before returning — and if that validation
 * fails, reloading from the {@link RpCertificateStore}'s source once and retrying before giving
 * up. This is the "certificate rotated mid-session" case: an operator rotates the on-disk
 * keystore, the in-memory cache is stale, the next request would otherwise fail outright, and
 * instead it self-heals by picking up the new certificate and retrying.
 *
 * <p>If the retry also fails, that second exception propagates — not the first — since it reflects
 * the current state of the (freshly reloaded) certificate.
 */
public final class HotReloadingCertificateResolver {

    private static final Logger log = LoggerFactory.getLogger(HotReloadingCertificateResolver.class);

    private final RpCertificateStore store;
    private final CertificateValidator validator;

    public HotReloadingCertificateResolver(RpCertificateStore store, CertificateValidator validator) {
        this.store = store;
        this.validator = validator;
    }

    /** The RP's current, validated key material — reloading and retrying once on failure. */
    public RpKeyMaterial resolveValid() throws CertificateLoadException, CertificateValidationException {
        RpKeyMaterial material = store.current();
        try {
            validator.validate(material.leaf(), material.chain());
            return material;
        } catch (CertificateValidationException firstFailure) {
            log.warn("Certificate validation failed ({}); reloading from source and retrying once",
                    firstFailure.getMessage());
            RpKeyMaterial reloaded = store.reload();
            validator.validate(reloaded.leaf(), reloaded.chain());
            log.info("Hot reload succeeded; request will proceed with the reloaded certificate");
            return reloaded;
        }
    }
}
