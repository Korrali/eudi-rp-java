package com.korrali.eudirp.support;

import com.korrali.eudirp.cert.RevocationChecker;
import com.korrali.eudirp.cert.RevocationSource;
import com.korrali.eudirp.cert.RevocationStatus;

import java.security.cert.X509Certificate;
import java.util.List;

/** Isolates the expired-certificate and certificate-rotation simulator scenarios from revocation
 * infrastructure — those scenarios are about temporal validity and hot reload, not revocation. */
public enum AlwaysGoodRevocationChecker implements RevocationChecker {
    INSTANCE;

    @Override
    public RevocationStatus check(X509Certificate cert, List<X509Certificate> chain) {
        return RevocationStatus.good(RevocationSource.CRL);
    }
}
