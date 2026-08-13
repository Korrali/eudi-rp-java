package com.korrali.eudirp.cert;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * Parses using BouncyCastle's ASN.1 reader, which accepts BER (including indefinite-length
 * encoding) as well as strict DER. This is the fallback path for certificates the JDK's
 * {@link StrictCertificateParser} rejects — never the first attempt, since BC's tolerance means it
 * will also happily parse some malformed input the JDK is right to reject.
 */
public final class TolerantCertificateParser implements CertificateParser {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public X509Certificate parse(byte[] derEncoded) throws MalformedCertificateException {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(derEncoded);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (Exception e) {
            throw new MalformedCertificateException(
                    "BouncyCastle tolerant parser also rejected the certificate: " + e.getMessage(), true, e);
        }
    }
}
