package com.korrali.eudirp.cert.support;

import com.korrali.eudirp.cert.TrustListProvider;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/** In-memory {@link TrustListProvider} for tests that don't need the file-backed default. */
public final class StaticTrustListProvider implements TrustListProvider {

    private final List<X509Certificate> anchors;

    public StaticTrustListProvider(X509Certificate... anchors) {
        this.anchors = List.of(anchors);
    }

    @Override
    public List<X509Certificate> trustAnchors() {
        return anchors;
    }

    @Override
    public Instant lastRefreshed() {
        return Instant.EPOCH;
    }
}
