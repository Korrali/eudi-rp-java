package com.korrali.eudirp.cert.support;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Test-only PKI helper: builds a throwaway CA and leaf certificates signed by it, plus CRLs, so
 * Phase 1 tests exercise real X.509/PKIX/CRL machinery instead of mocking it.
 */
public final class TestCertificates {

    private static final AtomicLong SERIAL = new AtomicLong(1);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestCertificates() {
    }

    public record IssuedCertificate(PrivateKey privateKey, X509Certificate certificate) {
    }

    public static IssuedCertificate selfSignedCa(String commonName) {
        return selfSignedCa(commonName, "RSA");
    }

    /**
     * @param keyAlgorithm {@code "RSA"} (2048-bit), or a JCA/BouncyCastle EC curve name
     *                     ({@code "secp256r1"}, {@code "brainpoolP256r1"}, {@code "brainpoolP384r1"},
     *                     {@code "brainpoolP512r1"}, ...) — see {@link #generateKeyPair(String)}.
     */
    public static IssuedCertificate selfSignedCa(String commonName, String keyAlgorithm) {
        try {
            KeyPair keyPair = generateKeyPair(keyAlgorithm);
            X500Name subject = new X500Name("CN=" + commonName);
            Instant now = Instant.now();
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject, nextSerial(), Date.from(now.minus(1, ChronoUnit.DAYS)),
                    Date.from(now.plus(3650, ChronoUnit.DAYS)), subject, keyPair.getPublic());
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));

            X509Certificate cert = sign(builder, keyPair.getPrivate());
            return new IssuedCertificate(keyPair.getPrivate(), cert);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build self-signed CA", e);
        }
    }

    public static IssuedCertificate leaf(IssuedCertificate ca, String commonName, Instant notBefore, Instant notAfter) {
        return leaf(ca, commonName, notBefore, notAfter, null, null);
    }

    public static IssuedCertificate leaf(IssuedCertificate ca, String commonName, Instant notBefore, Instant notAfter,
                                          String crlDistributionPointUri, String ocspResponderUri) {
        return leaf(ca, "RSA", commonName, notBefore, notAfter, crlDistributionPointUri, ocspResponderUri);
    }

    /** Same as the four-arg {@link #leaf}, but with the leaf's own key generated using
     * {@code keyAlgorithm} (see {@link #generateKeyPair(String)}) instead of always RSA. The CA's
     * signing algorithm is inferred from the CA's own key, independently. */
    public static IssuedCertificate leaf(IssuedCertificate ca, String keyAlgorithm, String commonName,
                                          Instant notBefore, Instant notAfter,
                                          String crlDistributionPointUri, String ocspResponderUri) {
        try {
            KeyPair keyPair = generateKeyPair(keyAlgorithm);
            X500Name issuer = new JcaX509CertificateHolder(ca.certificate()).getSubject();
            X500Name subject = new X500Name("CN=" + commonName);

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer, nextSerial(), Date.from(notBefore), Date.from(notAfter), subject, keyPair.getPublic());
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(ca.certificate()));

            if (crlDistributionPointUri != null) {
                GeneralName crlUri = new GeneralName(GeneralName.uniformResourceIdentifier, crlDistributionPointUri);
                DistributionPointName dpName = new DistributionPointName(new GeneralNames(crlUri));
                DistributionPoint distPoint = new DistributionPoint(dpName, null, null);
                builder.addExtension(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints, false,
                        new CRLDistPoint(new DistributionPoint[]{distPoint}));
            }
            if (ocspResponderUri != null) {
                org.bouncycastle.asn1.x509.AccessDescription ocspAccess = new org.bouncycastle.asn1.x509.AccessDescription(
                        org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, ocspResponderUri));
                builder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess, false,
                        new org.bouncycastle.asn1.x509.AuthorityInformationAccess(new org.bouncycastle.asn1.x509.AccessDescription[]{ocspAccess}));
            }

            X509Certificate cert = sign(builder, ca.privateKey());
            return new IssuedCertificate(keyPair.getPrivate(), cert);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build leaf certificate", e);
        }
    }

    public static X509CRL emptyCrl(IssuedCertificate ca) {
        return crl(ca, java.util.List.of());
    }

    public static X509CRL crl(IssuedCertificate ca, java.util.List<RevokedEntry> revoked) {
        try {
            X500Name issuer = new JcaX509CertificateHolder(ca.certificate()).getSubject();
            Instant now = Instant.now();
            X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, Date.from(now.minus(1, ChronoUnit.MINUTES)));
            builder.setNextUpdate(Date.from(now.plus(7, ChronoUnit.DAYS)));
            for (RevokedEntry entry : revoked) {
                builder.addCRLEntry(entry.serialNumber(), Date.from(entry.revokedAt()), entry.reasonCode());
            }
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(ca.certificate()));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ca.privateKey());
            X509CRLHolder holder = builder.build(signer);
            return new org.bouncycastle.cert.jcajce.JcaX509CRLConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(holder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build CRL", e);
        }
    }

    public record RevokedEntry(BigInteger serialNumber, Instant revokedAt, int reasonCode) {
        public static RevokedEntry of(X509Certificate cert, Instant revokedAt) {
            return new RevokedEntry(cert.getSerialNumber(), revokedAt, CRLReason.keyCompromise);
        }
    }

    /**
     * Rewrites a valid certificate's issuer Name to an empty SEQUENCE (zero RDNs) — structurally
     * valid ASN.1/BER, but rejected by the JDK's strict X.509 parser with "Empty issuer DN not
     * allowed in X509Certificates" (verified empirically against this build; BouncyCastle's
     * X509CertificateHolder does not perform the same check). See
     * {@code MalformedCertificateFixtureGenerator} for how this was chosen: several other
     * candidate malformations (BER indefinite-length encoding, duplicate extensions) were tried
     * first and empirically did NOT split strict-vs-tolerant on this JDK build — this one does.
     */
    public static byte[] withEmptyIssuerDn(byte[] derEncoded) {
        org.bouncycastle.asn1.ASN1Sequence certSeq = org.bouncycastle.asn1.ASN1Sequence.getInstance(derEncoded);
        org.bouncycastle.asn1.ASN1Sequence tbs = org.bouncycastle.asn1.ASN1Sequence.getInstance(certSeq.getObjectAt(0));

        org.bouncycastle.asn1.ASN1Sequence emptyName = new org.bouncycastle.asn1.DERSequence();
        org.bouncycastle.asn1.ASN1EncodableVector newTbsVec = new org.bouncycastle.asn1.ASN1EncodableVector();
        for (int i = 0; i < tbs.size(); i++) {
            newTbsVec.add(i == 3 ? emptyName : tbs.getObjectAt(i)); // index 3 = issuer Name
        }
        org.bouncycastle.asn1.ASN1Sequence newTbs = new org.bouncycastle.asn1.DERSequence(newTbsVec);

        org.bouncycastle.asn1.ASN1EncodableVector newCertVec = new org.bouncycastle.asn1.ASN1EncodableVector();
        newCertVec.add(newTbs);
        newCertVec.add(certSeq.getObjectAt(1)); // signatureAlgorithm, unchanged
        newCertVec.add(certSeq.getObjectAt(2)); // signature value, unchanged (won't cryptographically
        // verify against the mutated TBS — irrelevant here, this fixture exists to test parsing, not
        // signature verification, which is a separate, later stage in DefaultCertificateValidator)
        try {
            return new org.bouncycastle.asn1.DERSequence(newCertVec).getEncoded("DER");
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** Writes {@code leaf}'s key + [leaf, ...chain] certificate chain into a PKCS#12 file, for
     * {@code KeystoreCertificateSource}/hot-reload tests that need a real file on disk. */
    public static void writePkcs12(java.nio.file.Path path, char[] password, String alias,
                                    IssuedCertificate leaf, X509Certificate... chain) {
        try {
            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            java.security.cert.Certificate[] fullChain = new java.security.cert.Certificate[chain.length + 1];
            fullChain[0] = leaf.certificate();
            System.arraycopy(chain, 0, fullChain, 1, chain.length);
            keyStore.setKeyEntry(alias, leaf.privateKey(), password, fullChain);
            try (var out = java.nio.file.Files.newOutputStream(path)) {
                keyStore.store(out, password);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to write test PKCS#12 keystore", e);
        }
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, PrivateKey signerKey) throws Exception {
        // X.509's ecdsa-with-SHA256 AlgorithmIdentifier (OID 1.2.840.10045.4.3.2) doesn't encode a
        // curve — unlike JOSE's ES256, it's genuinely curve-agnostic, so no per-curve branching is
        // needed here (contrast PresentationRequestBuilder.signingAlgorithm(), which does need it).
        String signatureAlgorithm = "EC".equals(signerKey.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
    }

    private static BigInteger nextSerial() {
        return BigInteger.valueOf(SERIAL.getAndIncrement() + System.nanoTime());
    }

    private static KeyPair generateKeyPair() throws Exception {
        return generateKeyPair("RSA");
    }

    /** @param keyAlgorithm {@code "RSA"}, or a JCA/BouncyCastle EC curve name understood by
     *                      {@link org.bouncycastle.jce.spec.ECGenParameterSpec} (e.g.
     *                      {@code "secp256r1"}, {@code "brainpoolP256r1"}). */
    private static KeyPair generateKeyPair(String keyAlgorithm) throws Exception {
        if ("RSA".equals(keyAlgorithm)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new java.security.spec.ECGenParameterSpec(keyAlgorithm));
        return generator.generateKeyPair();
    }
}
