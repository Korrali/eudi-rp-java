package com.korrali.eudirp.cert;

/** Loads the RP's own key material fresh from wherever it's stored. */
public interface CertificateSource {

    RpKeyMaterial load() throws CertificateLoadException;
}
