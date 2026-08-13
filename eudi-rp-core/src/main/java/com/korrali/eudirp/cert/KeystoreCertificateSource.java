package com.korrali.eudirp.cert;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads an {@link RpKeyMaterial} from a PKCS#12 or JKS file on disk, re-reading the file on every
 * {@link #load()} call — callers that want caching wrap this in a {@link RpCertificateStore}.
 */
public final class KeystoreCertificateSource implements CertificateSource {

    private final Path keystorePath;
    private final KeystoreType type;
    private final char[] storePassword;
    private final String alias;
    private final char[] keyPassword;

    public KeystoreCertificateSource(Path keystorePath, KeystoreType type, char[] storePassword,
                                      String alias, char[] keyPassword) {
        this.keystorePath = keystorePath;
        this.type = type;
        this.storePassword = storePassword.clone();
        this.alias = alias;
        this.keyPassword = keyPassword.clone();
    }

    @Override
    public RpKeyMaterial load() throws CertificateLoadException {
        if (!Files.isReadable(keystorePath)) {
            throw new CertificateLoadException("Keystore not readable: " + keystorePath);
        }
        try (InputStream in = Files.newInputStream(keystorePath)) {
            KeyStore keyStore = KeyStore.getInstance(type.javaKeystoreType());
            keyStore.load(in, storePassword);

            if (!keyStore.containsAlias(alias)) {
                throw new CertificateLoadException(
                        "Keystore " + keystorePath + " has no entry under alias '" + alias + "'");
            }

            Key key = keyStore.getKey(alias, keyPassword);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new CertificateLoadException(
                        "Alias '" + alias + "' in " + keystorePath + " is not a private key entry");
            }

            Certificate[] chain = keyStore.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                throw new CertificateLoadException(
                        "Alias '" + alias + "' in " + keystorePath + " has no certificate chain");
            }

            X509Certificate leaf = asX509(chain[0]);
            List<X509Certificate> rest = new ArrayList<>(chain.length - 1);
            for (int i = 1; i < chain.length; i++) {
                rest.add(asX509(chain[i]));
            }

            return new RpKeyMaterial(privateKey, leaf, rest);
        } catch (IOException | GeneralSecurityException e) {
            throw new CertificateLoadException("Failed to load keystore " + keystorePath + ": " + e.getMessage(), e);
        }
    }

    private static X509Certificate asX509(Certificate certificate) throws CertificateLoadException {
        if (certificate instanceof X509Certificate x509) {
            return x509;
        }
        throw new CertificateLoadException("Non-X.509 certificate encountered: " + certificate.getType());
    }
}
