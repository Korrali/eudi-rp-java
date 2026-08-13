package com.korrali.eudirp.spring;

import com.korrali.eudirp.cert.KeystoreType;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.nio.file.Path;

/**
 * Configuration for the EUDI relying party starter, prefix {@code eudirp}. Every property here
 * was added because a real deployment needs to point at its own keystore/trust-list/declared
 * attributes — DESIGN.md's "every configuration property is a future support question" rule means
 * nothing beyond that is exposed.
 */
@ConfigurationProperties(prefix = "eudirp")
public class EudiRpProperties {

    /** RP access certificate keystore. */
    @NestedConfigurationProperty
    private final Certificate certificate = new Certificate();

    /** Trust anchors for chain validation. */
    @NestedConfigurationProperty
    private final TrustList trustList = new TrustList();

    /** The RP's own declared attribute set. */
    @NestedConfigurationProperty
    private final Registration registration = new Registration();

    /** Revocation-checking behavior. */
    @NestedConfigurationProperty
    private final Revocation revocation = new Revocation();

    public Certificate getCertificate() {
        return certificate;
    }

    public TrustList getTrustList() {
        return trustList;
    }

    public Registration getRegistration() {
        return registration;
    }

    public Revocation getRevocation() {
        return revocation;
    }

    public static class Certificate {
        /** Path to the PKCS#12 or JKS keystore holding the RP's access certificate and private key. */
        private Path keystorePath;
        private KeystoreType keystoreType = KeystoreType.PKCS12;
        private String storePassword;
        private String alias = "rp";
        private String keyPassword;

        public Path getKeystorePath() {
            return keystorePath;
        }

        public void setKeystorePath(Path keystorePath) {
            this.keystorePath = keystorePath;
        }

        public KeystoreType getKeystoreType() {
            return keystoreType;
        }

        public void setKeystoreType(KeystoreType keystoreType) {
            this.keystoreType = keystoreType;
        }

        public String getStorePassword() {
            return storePassword;
        }

        public void setStorePassword(String storePassword) {
            this.storePassword = storePassword;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getKeyPassword() {
            return keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
            this.keyPassword = keyPassword;
        }
    }

    public static class TrustList {
        /** A PEM bundle file, or a directory of {@code .pem}/{@code .crt} files. */
        private Path path;

        public Path getPath() {
            return path;
        }

        public void setPath(Path path) {
            this.path = path;
        }
    }

    public static class Registration {
        /** One declared attribute path per line — see {@code LocalRegistrationMetadataProvider}. */
        private Path declaredAttributesFile;

        public Path getDeclaredAttributesFile() {
            return declaredAttributesFile;
        }

        public void setDeclaredAttributesFile(Path declaredAttributesFile) {
            this.declaredAttributesFile = declaredAttributesFile;
        }
    }

    public static class Revocation {
        /** Whether an undeterminable revocation status is treated as untrusted (default, safer)
         * or ignored (fail-open) — see {@code DefaultCertificateValidator}. */
        private boolean failClosed = true;

        public boolean isFailClosed() {
            return failClosed;
        }

        public void setFailClosed(boolean failClosed) {
            this.failClosed = failClosed;
        }
    }
}
