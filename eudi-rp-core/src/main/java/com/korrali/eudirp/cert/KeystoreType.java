package com.korrali.eudirp.cert;

/** The two keystore formats Phase 1 loads RP access certificates from. */
public enum KeystoreType {
    PKCS12("PKCS12"),
    JKS("JKS");

    private final String javaKeystoreType;

    KeystoreType(String javaKeystoreType) {
        this.javaKeystoreType = javaKeystoreType;
    }

    /** The name to pass to {@link java.security.KeyStore#getInstance(String)}. */
    public String javaKeystoreType() {
        return javaKeystoreType;
    }
}
