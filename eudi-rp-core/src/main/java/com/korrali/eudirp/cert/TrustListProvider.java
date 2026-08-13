package com.korrali.eudirp.cert;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * Supplies the CA certificates a chain must build to. See DESIGN.md §4 — this is a narrow,
 * stable extension point; only a local file-based default ships in this library.
 */
public interface TrustListProvider {

    List<X509Certificate> trustAnchors();

    /** When the underlying trust list was last (re)loaded, for freshness reporting. */
    Instant lastRefreshed();
}
