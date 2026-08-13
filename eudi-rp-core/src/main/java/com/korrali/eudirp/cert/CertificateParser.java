package com.korrali.eudirp.cert;

import java.security.cert.X509Certificate;

/** Turns raw DER bytes into an {@link X509Certificate}. */
public interface CertificateParser {

    X509Certificate parse(byte[] derEncoded) throws MalformedCertificateException;
}
