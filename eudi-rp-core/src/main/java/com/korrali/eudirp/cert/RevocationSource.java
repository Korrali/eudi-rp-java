package com.korrali.eudirp.cert;

/** Which mechanism actually produced a revocation determination. */
public enum RevocationSource {
    CRL,
    OCSP
}
