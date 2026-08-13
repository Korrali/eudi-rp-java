package com.korrali.eudirp.cert;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * An RP access certificate and the private key it was issued for, plus the chain up to (but not
 * including) the trust anchor. This is what a keystore load produces and what a request signer
 * consumes.
 */
public record RpKeyMaterial(PrivateKey privateKey, X509Certificate leaf, List<X509Certificate> chain) {

    public RpKeyMaterial {
        chain = List.copyOf(chain);
    }
}
