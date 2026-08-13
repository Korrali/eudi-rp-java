package com.korrali.eudirp.cert;

import java.util.concurrent.atomic.AtomicReference;

/** Caches the result of a {@link CertificateSource}, reloading only on explicit request. */
public final class DefaultRpCertificateStore implements RpCertificateStore {

    private final CertificateSource source;
    private final AtomicReference<RpKeyMaterial> cached = new AtomicReference<>();

    public DefaultRpCertificateStore(CertificateSource source) {
        this.source = source;
    }

    @Override
    public RpKeyMaterial current() throws CertificateLoadException {
        RpKeyMaterial existing = cached.get();
        return existing != null ? existing : reload();
    }

    @Override
    public RpKeyMaterial reload() throws CertificateLoadException {
        RpKeyMaterial fresh = source.load();
        cached.set(fresh);
        return fresh;
    }
}
