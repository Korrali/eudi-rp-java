package com.korrali.eudirp.demo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
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
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/**
 * Generates a throwaway demo CA + RP access certificate + declared-attributes file on first run,
 * so the demo works with zero manual setup ("verify in thirty seconds") — this is a proof, not a
 * product; a real deployment provisions its own access certificate through its Member State's
 * registration process (DESIGN.md §2.2), never like this.
 *
 * <p>Called from {@code main()} <em>before</em> {@code SpringApplication.run(...)}, not as a
 * {@code @Component}/{@code ApplicationReadyEvent} listener — {@code LocalFileTrustListProvider}
 * reads its trust file eagerly in its constructor, which runs during context refresh, before any
 * post-startup event would fire. The files must exist before the context starts, not after.
 */
public final class DemoPkiBootstrap {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private DemoPkiBootstrap() {
    }

    public static void generateIfMissing(Path dataDir) throws Exception {
        Files.createDirectories(dataDir);
        Path keystorePath = dataDir.resolve("rp.p12");
        Path trustPath = dataDir.resolve("trust.pem");
        Path declaredAttributesPath = dataDir.resolve("declared-attributes.txt");

        if (!Files.exists(declaredAttributesPath)) {
            Files.writeString(declaredAttributesPath, String.join("\n",
                    "given_name", "family_name", "birth_date", "street_address", "locality", "postal_code", "country") + "\n");
        }
        if (Files.exists(keystorePath) && Files.exists(trustPath)) {
            return;
        }

        KeyPair caKeyPair = generateKeyPair();
        X500Name caName = new X500Name("CN=eudi-rp-java Demo Access CA,O=eudi-rp-java demo,C=EU");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(1), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)), caName, caKeyPair.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate caCert = sign(caBuilder, caKeyPair.getPrivate());

        KeyPair leafKeyPair = generateKeyPair();
        X500Name leafName = new X500Name("CN=eudi-rp-java-demo.korrali.com,O=Korrali,C=EU");
        JcaX509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(2), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(90, ChronoUnit.DAYS)), leafName, leafKeyPair.getPublic());
        leafBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        X509Certificate leafCert = sign(leafBuilder, caKeyPair.getPrivate());

        char[] password = "demo-password".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("rp", leafKeyPair.getPrivate(), password, new Certificate[]{leafCert, caCert});
        try (OutputStream out = Files.newOutputStream(keystorePath)) {
            keyStore.store(out, password);
        }
        Files.writeString(trustPath, toPem(caCert));
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, PrivateKey signerKey) throws Exception {
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
