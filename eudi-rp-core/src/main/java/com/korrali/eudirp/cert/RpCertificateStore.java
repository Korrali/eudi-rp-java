package com.korrali.eudirp.cert;

/**
 * Holds the RP's current key material, cached, with an explicit force-refresh path. Reading from
 * disk on every signing operation would be wasteful; never refreshing means a rotated certificate
 * on disk is invisible until process restart. {@link HotReloadingCertificateResolver} is what
 * decides *when* to call {@link #reload()} in response to a validation failure — this interface
 * only exposes the two primitives it needs.
 */
public interface RpCertificateStore {

    /** The cached key material, loading it for the first time if this is the first call. */
    RpKeyMaterial current() throws CertificateLoadException;

    /** Forces a fresh read from the underlying {@link CertificateSource}, replacing the cache. */
    RpKeyMaterial reload() throws CertificateLoadException;
}
