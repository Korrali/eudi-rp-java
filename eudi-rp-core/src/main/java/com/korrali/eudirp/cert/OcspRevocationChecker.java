package com.korrali.eudirp.cert;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Direct OCSP check (RFC 6960): reads the Authority Information Access extension for the OCSP
 * responder URL, sends a request over HTTP POST, and verifies the signed response. No caching, no
 * nonce persistence across calls. See DESIGN.md §4.
 */
public final class OcspRevocationChecker implements RevocationChecker {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final HttpClient httpClient;

    public OcspRevocationChecker() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public OcspRevocationChecker(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public RevocationStatus check(X509Certificate cert, List<X509Certificate> chain) throws RevocationCheckException {
        if (chain.isEmpty()) {
            throw new RevocationCheckException("No issuer certificate in chain; cannot build an OCSP request");
        }
        X509Certificate issuer = chain.get(0);
        URI responderUri = ocspResponderUri(cert)
                .orElseThrow(() -> new RevocationCheckException(
                        "Certificate has no OCSP responder in its Authority Information Access extension"));

        try {
            DigestCalculatorProvider digestCalculatorProvider =
                    new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
            CertificateID certificateId = new CertificateID(
                    digestCalculatorProvider.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuer),
                    cert.getSerialNumber());

            OCSPReqBuilder requestBuilder = new OCSPReqBuilder();
            requestBuilder.addRequest(certificateId);
            OCSPReq request = requestBuilder.build();

            byte[] responseBytes = sendOcspRequest(responderUri, request.getEncoded());
            OCSPResp response = new OCSPResp(responseBytes);
            if (response.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
                throw new RevocationCheckException("OCSP responder returned non-successful status: " + response.getStatus());
            }

            BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            verifyResponseSignature(basicResponse, issuer);

            for (SingleResp singleResponse : basicResponse.getResponses()) {
                if (!singleResponse.getCertID().equals(certificateId)) {
                    continue;
                }
                CertificateStatus status = singleResponse.getCertStatus();
                if (status == null) {
                    return RevocationStatus.good(RevocationSource.OCSP);
                }
                if (status instanceof RevokedStatus revoked) {
                    Instant revokedAt = revoked.getRevocationTime().toInstant();
                    RevocationReason reason = revoked.hasRevocationReason()
                            ? mapReason(revoked.getRevocationReason())
                            : RevocationReason.NOT_SPECIFIED;
                    return RevocationStatus.revoked(RevocationSource.OCSP, revokedAt, reason);
                }
                throw new RevocationCheckException("OCSP responder returned UNKNOWN status for this certificate");
            }
            throw new RevocationCheckException("OCSP response did not include a status for the requested certificate");
        } catch (OCSPException | OperatorCreationException | IOException | CertificateEncodingException e) {
            throw new RevocationCheckException("OCSP check against " + responderUri + " failed: " + e.getMessage(), e);
        }
    }

    private static void verifyResponseSignature(BasicOCSPResp basicResponse, X509Certificate issuer)
            throws RevocationCheckException {
        try {
            X509CertificateHolder[] embeddedCerts = basicResponse.getCerts();
            X509CertificateHolder signerHolder = embeddedCerts.length > 0
                    ? embeddedCerts[0]
                    : new JcaX509CertificateHolder(issuer);
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signerHolder);
            if (!basicResponse.isSignatureValid(verifierProvider)) {
                throw new RevocationCheckException("OCSP response signature did not verify");
            }
        } catch (OCSPException | OperatorCreationException | CertificateException e) {
            throw new RevocationCheckException("Failed to verify OCSP response signature: " + e.getMessage(), e);
        }
    }

    private byte[] sendOcspRequest(URI uri, byte[] encodedRequest) throws RevocationCheckException {
        HttpRequest httpRequest = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/ocsp-request")
                .header("Accept", "application/ocsp-response")
                .POST(HttpRequest.BodyPublishers.ofByteArray(encodedRequest))
                .build();
        try {
            HttpResponse<byte[]> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
            if (httpResponse.statusCode() != 200) {
                throw new RevocationCheckException("OCSP responder at " + uri + " returned HTTP " + httpResponse.statusCode());
            }
            return httpResponse.body();
        } catch (IOException e) {
            throw new RevocationCheckException("Failed to reach OCSP responder at " + uri + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RevocationCheckException("Interrupted while awaiting OCSP response from " + uri, e);
        }
    }

    private static RevocationReason mapReason(int bcCrlReason) {
        if (bcCrlReason == CRLReason.unspecified) return RevocationReason.UNSPECIFIED;
        if (bcCrlReason == CRLReason.keyCompromise) return RevocationReason.KEY_COMPROMISE;
        if (bcCrlReason == CRLReason.cACompromise) return RevocationReason.CA_COMPROMISE;
        if (bcCrlReason == CRLReason.affiliationChanged) return RevocationReason.AFFILIATION_CHANGED;
        if (bcCrlReason == CRLReason.superseded) return RevocationReason.SUPERSEDED;
        if (bcCrlReason == CRLReason.cessationOfOperation) return RevocationReason.CESSATION_OF_OPERATION;
        if (bcCrlReason == CRLReason.certificateHold) return RevocationReason.CERTIFICATE_HOLD;
        if (bcCrlReason == CRLReason.removeFromCRL) return RevocationReason.REMOVE_FROM_CRL;
        if (bcCrlReason == CRLReason.privilegeWithdrawn) return RevocationReason.PRIVILEGE_WITHDRAWN;
        if (bcCrlReason == CRLReason.aACompromise) return RevocationReason.AA_COMPROMISE;
        return RevocationReason.NOT_SPECIFIED;
    }

    private static Optional<URI> ocspResponderUri(X509Certificate cert) throws RevocationCheckException {
        byte[] extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extensionValue == null) {
            return Optional.empty();
        }
        try {
            byte[] octets = ((ASN1OctetString) new ASN1InputStream(extensionValue).readObject()).getOctets();
            AuthorityInformationAccess aia;
            try (ASN1InputStream octetIn = new ASN1InputStream(octets)) {
                aia = AuthorityInformationAccess.getInstance(octetIn.readObject());
            }
            for (AccessDescription description : aia.getAccessDescriptions()) {
                if (!description.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    continue;
                }
                GeneralName location = description.getAccessLocation();
                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return Optional.of(URI.create(location.getName().toString()));
                }
            }
            return Optional.empty();
        } catch (IOException e) {
            throw new RevocationCheckException("Failed to parse Authority Information Access extension: " + e.getMessage(), e);
        }
    }
}
