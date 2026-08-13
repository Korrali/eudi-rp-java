package com.korrali.eudirp.support;

import com.korrali.eudirp.cert.TrustListProvider;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/** A one-anchor {@link TrustListProvider} for the failure simulator, which builds a fresh
 * throwaway CA per scenario rather than using the demo's real trust list. */
public final class SingleCertTrustListProvider implements TrustListProvider {

    private final X509Certificate anchor;

    public SingleCertTrustListProvider(X509Certificate anchor) {
        this.anchor = anchor;
    }

    @Override
    public List<X509Certificate> trustAnchors() {
        return List.of(anchor);
    }

    @Override
    public Instant lastRefreshed() {
        return Instant.now();
    }
}
