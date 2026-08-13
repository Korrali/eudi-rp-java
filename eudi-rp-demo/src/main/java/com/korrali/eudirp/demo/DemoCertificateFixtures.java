package com.korrali.eudirp.demo;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/**
 * Builds real (not mocked) certificates/CRLs on demand for the demo's failure simulator — same
 * BouncyCastle machinery as eudi-rp-core's own test fixtures (which live in test sources there and
 * aren't visible to this module), reimplemented at demo scope since the simulator needs to build
 * these live, interactively, not just once at test time.
 */
final class DemoCertificateFixtures {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    record IssuedCertificate(PrivateKey privateKey, X509Certificate certificate) {
    }

    private DemoCertificateFixtures() {
    }

    static IssuedCertificate selfSignedCa(String commonName) throws Exception {
        KeyPair keyPair = generateKeyPair();
        X500Name subject = new X500Name("CN=" + commonName);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.nanoTime()), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)), subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new IssuedCertificate(keyPair.getPrivate(), sign(builder, keyPair.getPrivate()));
    }

    static IssuedCertificate leaf(IssuedCertificate ca, String commonName, Instant notBefore, Instant notAfter,
                                   String crlUri) throws Exception {
        KeyPair keyPair = generateKeyPair();
        X500Name issuer = new JcaX509CertificateHolder(ca.certificate()).getSubject();
        X500Name subject = new X500Name("CN=" + commonName);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(System.nanoTime()), Date.from(notBefore), Date.from(notAfter),
                subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        if (crlUri != null) {
            var name = new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier, crlUri);
            var dpName = new org.bouncycastle.asn1.x509.DistributionPointName(new org.bouncycastle.asn1.x509.GeneralNames(name));
            var point = new org.bouncycastle.asn1.x509.DistributionPoint(dpName, null, null);
            builder.addExtension(Extension.cRLDistributionPoints, false,
                    new org.bouncycastle.asn1.x509.CRLDistPoint(new org.bouncycastle.asn1.x509.DistributionPoint[]{point}));
        }
        return new IssuedCertificate(keyPair.getPrivate(), sign(builder, ca.privateKey()));
    }

    static X509CRL crlRevoking(IssuedCertificate ca, X509Certificate revokedCert) throws Exception {
        X500Name issuer = new JcaX509CertificateHolder(ca.certificate()).getSubject();
        Instant now = Instant.now();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, Date.from(now.minus(1, ChronoUnit.MINUTES)));
        builder.setNextUpdate(Date.from(now.plus(7, ChronoUnit.DAYS)));
        builder.addCRLEntry(revokedCert.getSerialNumber(), Date.from(now.minus(1, ChronoUnit.HOURS)),
                org.bouncycastle.asn1.x509.CRLReason.keyCompromise);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ca.privateKey());
        return new JcaX509CRLConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(builder.build(signer));
    }

    /** Same empirically-verified malformation as eudi-rp-core's MalformedCertificateFixtureGenerator:
     * an empty issuer Name, which the JDK's strict X.509 parser rejects and BouncyCastle accepts. */
    static byte[] withEmptyIssuerDn(X509Certificate cert) throws Exception {
        byte[] der = cert.getEncoded();
        ASN1Sequence certSeq = ASN1Sequence.getInstance(der);
        ASN1Sequence tbs = ASN1Sequence.getInstance(certSeq.getObjectAt(0));

        ASN1Sequence emptyName = new DERSequence();
        ASN1EncodableVector newTbsVec = new ASN1EncodableVector();
        for (int i = 0; i < tbs.size(); i++) {
            newTbsVec.add(i == 3 ? emptyName : tbs.getObjectAt(i));
        }
        ASN1Sequence newTbs = new DERSequence(newTbsVec);

        ASN1EncodableVector newCertVec = new ASN1EncodableVector();
        newCertVec.add(newTbs);
        newCertVec.add(certSeq.getObjectAt(1));
        newCertVec.add(certSeq.getObjectAt(2));
        return new DERSequence(newCertVec).getEncoded("DER");
    }

    static void writePkcs12(java.nio.file.Path path, char[] password, IssuedCertificate leaf, X509Certificate ca) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("rp", leaf.privateKey(), password, new Certificate[]{leaf.certificate(), ca});
        try (var out = java.nio.file.Files.newOutputStream(path)) {
            keyStore.store(out, password);
        }
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
}
