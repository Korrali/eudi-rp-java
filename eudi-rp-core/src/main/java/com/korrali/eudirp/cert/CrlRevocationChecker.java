package com.korrali.eudirp.cert;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * Direct CRL check: reads the CRL Distribution Points extension off the certificate, fetches the
 * CRL from the first distribution point (http/https/file URL), and looks up the certificate's
 * serial number in it. No caching — every {@link #check} call fetches fresh. See DESIGN.md §4.
 */
public final class CrlRevocationChecker implements RevocationChecker {

    @Override
    public RevocationStatus check(X509Certificate cert, List<X509Certificate> chain) throws RevocationCheckException {
        URI crlUri = crlDistributionPointUri(cert)
                .orElseThrow(() -> new RevocationCheckException(
                        "Certificate has no CRL Distribution Points extension"));

        X509CRL crl = fetchCrl(crlUri);

        X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
        if (entry == null) {
            return RevocationStatus.good(RevocationSource.CRL);
        }

        Instant revokedAt = entry.getRevocationDate().toInstant();
        RevocationReason reason = mapReason(entry);
        return RevocationStatus.revoked(RevocationSource.CRL, revokedAt, reason);
    }

    private static X509CRL fetchCrl(URI uri) throws RevocationCheckException {
        try (InputStream in = uri.toURL().openStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509CRL) factory.generateCRL(in);
        } catch (IOException | CRLException | CertificateException e) {
            throw new RevocationCheckException("Failed to fetch/parse CRL from " + uri + ": " + e.getMessage(), e);
        }
    }

    private static RevocationReason mapReason(X509CRLEntry entry) {
        java.security.cert.CRLReason jdkReason = entry.getRevocationReason();
        if (jdkReason == null) {
            return RevocationReason.NOT_SPECIFIED;
        }
        return switch (jdkReason) {
            case KEY_COMPROMISE -> RevocationReason.KEY_COMPROMISE;
            case CA_COMPROMISE -> RevocationReason.CA_COMPROMISE;
            case AFFILIATION_CHANGED -> RevocationReason.AFFILIATION_CHANGED;
            case SUPERSEDED -> RevocationReason.SUPERSEDED;
            case CESSATION_OF_OPERATION -> RevocationReason.CESSATION_OF_OPERATION;
            case CERTIFICATE_HOLD -> RevocationReason.CERTIFICATE_HOLD;
            case REMOVE_FROM_CRL -> RevocationReason.REMOVE_FROM_CRL;
            case PRIVILEGE_WITHDRAWN -> RevocationReason.PRIVILEGE_WITHDRAWN;
            case AA_COMPROMISE -> RevocationReason.AA_COMPROMISE;
            case UNSPECIFIED -> RevocationReason.UNSPECIFIED;
            default -> RevocationReason.NOT_SPECIFIED;
        };
    }

    private static java.util.Optional<URI> crlDistributionPointUri(X509Certificate cert) throws RevocationCheckException {
        byte[] extensionValue = cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return java.util.Optional.empty();
        }
        try {
            byte[] octets = ((ASN1OctetString) new ASN1InputStream(extensionValue).readObject()).getOctets();
            CRLDistPoint distPoint;
            try (ASN1InputStream octetIn = new ASN1InputStream(octets)) {
                distPoint = CRLDistPoint.getInstance(octetIn.readObject());
            }
            for (DistributionPoint point : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = point.getDistributionPoint();
                if (dpn == null || dpn.getType() != DistributionPointName.FULL_NAME) {
                    continue;
                }
                GeneralNames generalNames = GeneralNames.getInstance(dpn.getName());
                for (GeneralName name : generalNames.getNames()) {
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return java.util.Optional.of(URI.create(name.getName().toString()));
                    }
                }
            }
            return java.util.Optional.empty();
        } catch (IOException e) {
            throw new RevocationCheckException("Failed to parse CRL Distribution Points extension: " + e.getMessage(), e);
        }
    }
}
