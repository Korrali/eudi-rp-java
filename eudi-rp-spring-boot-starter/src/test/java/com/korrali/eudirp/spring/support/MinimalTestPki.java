package com.korrali.eudirp.spring.support;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/** Minimal self-signed CA+leaf generator for the starter's auto-configuration test — just enough
 * to produce a real keystore file and trust anchor PEM, not a full PKI test harness. */
public final class MinimalTestPki {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private MinimalTestPki() {
    }

    public record Setup(Path keystorePath, Path trustAnchorPath, char[] password, String alias) {
    }

    public static Setup writeCaSignedLeafKeystore(Path dir) throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        X500Name caName = new X500Name("CN=Starter Test CA");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(1), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)), caName, caKeyPair.getPublic());
        caBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate caCert = sign(caBuilder, caKeyPair.getPrivate());

        KeyPair leafKeyPair = generateKeyPair();
        X500Name leafName = new X500Name("CN=starter-test-rp.example.org");
        JcaX509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(2), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)), leafName, leafKeyPair.getPublic());
        leafBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
        X509Certificate leafCert = sign(leafBuilder, caKeyPair.getPrivate());

        char[] password = "changeit".toCharArray();
        String alias = "rp";
        Path keystorePath = dir.resolve("rp.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, leafKeyPair.getPrivate(), password, new Certificate[]{leafCert, caCert});
        try (OutputStream out = Files.newOutputStream(keystorePath)) {
            keyStore.store(out, password);
        }

        Path trustAnchorPath = dir.resolve("trust.pem");
        Files.writeString(trustAnchorPath, toPem(caCert));

        return new Setup(keystorePath, trustAnchorPath, password, alias);
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, java.security.PrivateKey signerKey) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String toPem(X509Certificate cert) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }
}
