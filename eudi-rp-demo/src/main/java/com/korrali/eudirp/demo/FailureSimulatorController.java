package com.korrali.eudirp.demo;

import com.korrali.eudirp.cert.CompositeRevocationChecker;
import com.korrali.eudirp.cert.CrlRevocationChecker;
import com.korrali.eudirp.cert.DefaultCertificateValidator;
import com.korrali.eudirp.cert.DefaultRpCertificateStore;
import com.korrali.eudirp.cert.ExpiredCertificateException;
import com.korrali.eudirp.cert.HotReloadingCertificateResolver;
import com.korrali.eudirp.cert.KeystoreCertificateSource;
import com.korrali.eudirp.cert.KeystoreType;
import com.korrali.eudirp.cert.MalformedCertificateException;
import com.korrali.eudirp.cert.OcspRevocationChecker;
import com.korrali.eudirp.cert.RevokedCertificateException;
import com.korrali.eudirp.cert.RpKeyMaterial;
import com.korrali.eudirp.cert.StrictCertificateParser;
import com.korrali.eudirp.cert.ToleratingCertificateParser;
import com.korrali.eudirp.cert.TolerantCertificateParser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The required, non-optional part of this demo (see project brief): each endpoint runs one of the
 * four certificate failure paths live, for real, against real BouncyCastle/JDK machinery — not
 * canned responses. Every scenario shows what failed, which code path handled it, and what a
 * caller would see.
 */
@RestController
@RequestMapping("/api/simulate")
public class FailureSimulatorController {

    @PostMapping("/expired-certificate")
    public Map<String, Object> expiredCertificate() throws Exception {
        DemoCertificateFixtures.IssuedCertificate ca = DemoCertificateFixtures.selfSignedCa("Simulator CA");
        Instant now = Instant.now();
        Instant notAfter = now.minus(3, ChronoUnit.DAYS);
        DemoCertificateFixtures.IssuedCertificate leaf = DemoCertificateFixtures.leaf(
                ca, "expired-rp.example.org", now.minus(30, ChronoUnit.DAYS), notAfter, null);

        var trustList = new com.korrali.eudirp.support.SingleCertTrustListProvider(ca.certificate());
        var revocation = com.korrali.eudirp.support.AlwaysGoodRevocationChecker.INSTANCE;
        var validator = new DefaultCertificateValidator(trustList, revocation);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scenario", "Expired RP access certificate");
        result.put("codePath", "DefaultCertificateValidator.validate() -> checkTemporalValidity()");
        try {
            validator.validate(leaf.certificate(), List.of(ca.certificate()));
            result.put("outcome", "UNEXPECTED: validation passed");
        } catch (ExpiredCertificateException e) {
            result.put("outcome", "failed as expected");
            result.put("exceptionType", e.getClass().getSimpleName());
            result.put("expiredAt", e.expiredAt().toString());
            result.put("message", e.getMessage());
            result.put("callerSees", "a typed ExpiredCertificateException with the exact expiry timestamp — "
                    + "not a generic CertificateException, so calling code can branch on it without string-matching a message.");
        }
        return result;
    }

    @PostMapping("/revoked-certificate")
    public Map<String, Object> revokedCertificate(@org.springframework.web.bind.annotation.RequestParam(defaultValue = "./demo-data") String dataDir) throws Exception {
        Path tempDir = Files.createTempDirectory("eudirp-demo-revoked-");
        DemoCertificateFixtures.IssuedCertificate ca = DemoCertificateFixtures.selfSignedCa("Simulator CA");
        Path crlFile = tempDir.resolve("simulator.crl");
        Instant now = Instant.now();
        DemoCertificateFixtures.IssuedCertificate leaf = DemoCertificateFixtures.leaf(
                ca, "revoked-rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS),
                crlFile.toUri().toString());
        Files.write(crlFile, DemoCertificateFixtures.crlRevoking(ca, leaf.certificate()).getEncoded());

        // No OCSP responder is configured for this simulator cert, so OCSP fails first (no AIA
        // extension) and the checker falls back to CRL, which does have an answer — this is the
        // real CompositeRevocationChecker behavior, not staged.
        var checker = CompositeRevocationChecker.ocspThenCrl();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scenario", "Revoked RP access certificate");
        result.put("codePath", "CompositeRevocationChecker.check() -> OcspRevocationChecker (no responder configured, fails) -> falls back to CrlRevocationChecker (succeeds)");
        try {
            var status = checker.check(leaf.certificate(), List.of(ca.certificate()));
            if (status.revoked()) {
                result.put("outcome", "revoked, caught by " + status.source());
                result.put("revocationSource", status.source().name());
                result.put("revokedAt", status.revokedAt().map(Object::toString).orElse(null));
                result.put("reason", status.reason().map(Enum::name).orElse(null));
                result.put("callerSees", "a RevocationStatus.revoked()=true with source=CRL — the caller knows exactly which "
                        + "mechanism caught it, not just that the certificate is bad.");
            } else {
                result.put("outcome", "UNEXPECTED: reported not revoked");
            }
        } finally {
            Files.deleteIfExists(crlFile);
            Files.deleteIfExists(tempDir);
        }
        return result;
    }

    @PostMapping("/malformed-certificate")
    public Map<String, Object> malformedCertificate() throws Exception {
        DemoCertificateFixtures.IssuedCertificate ca = DemoCertificateFixtures.selfSignedCa("Simulator CA");
        Instant now = Instant.now();
        DemoCertificateFixtures.IssuedCertificate leaf = DemoCertificateFixtures.leaf(
                ca, "malformed-rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS), null);
        byte[] malformedDer = DemoCertificateFixtures.withEmptyIssuerDn(leaf.certificate());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scenario", "Malformed certificate (empty issuer DN — a real, empirically-verified split, "
                + "not the originally-assumed BER-indefinite-length case; see eudi-rp-core's MalformedCertificateFixtureGenerator javadoc)");

        String strictError = null;
        try {
            new StrictCertificateParser().parse(malformedDer);
            result.put("strictPathResult", "UNEXPECTED: strict path accepted it");
        } catch (MalformedCertificateException e) {
            strictError = e.getMessage();
            result.put("strictPathResult", "rejected");
            result.put("strictPathError", strictError);
        }

        try {
            new TolerantCertificateParser().parse(malformedDer);
            result.put("tolerantPathResult", "accepted");
        } catch (MalformedCertificateException e) {
            result.put("tolerantPathResult", "UNEXPECTED: tolerant path also rejected it: " + e.getMessage());
        }

        var composite = new ToleratingCertificateParser();
        try {
            var cert = composite.parse(malformedDer);
            result.put("outcome", "flow completed successfully via the tolerant fallback");
            result.put("codePath", "ToleratingCertificateParser: StrictCertificateParser failed -> TolerantCertificateParser (BouncyCastle) engaged and succeeded");
            result.put("parsedSubject", cert.getSubjectX500Principal().getName());
            result.put("callerSees", "a successfully parsed certificate, plus a logged warning that the tolerant path engaged — "
                    + "the request proceeds instead of failing outright on a certificate a strict-only parser would reject.");
        } catch (MalformedCertificateException e) {
            result.put("outcome", "UNEXPECTED: composite parser failed too");
        }
        return result;
    }

    @PostMapping("/certificate-rotation")
    public Map<String, Object> certificateRotation() throws Exception {
        Path tempDir = Files.createTempDirectory("eudirp-demo-rotation-");
        Path keystorePath = tempDir.resolve("rotating-rp.p12");
        char[] password = "demo-password".toCharArray();

        DemoCertificateFixtures.IssuedCertificate ca = DemoCertificateFixtures.selfSignedCa("Simulator CA");
        Instant now = Instant.now();
        DemoCertificateFixtures.IssuedCertificate expiredLeaf = DemoCertificateFixtures.leaf(
                ca, "rotating-rp.example.org", now.minus(60, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS), null);
        DemoCertificateFixtures.writePkcs12(keystorePath, password, expiredLeaf, ca.certificate());

        var source = new KeystoreCertificateSource(keystorePath, KeystoreType.PKCS12, password, "rp", password);
        var certStore = new DefaultRpCertificateStore(source);
        var trustList = new com.korrali.eudirp.support.SingleCertTrustListProvider(ca.certificate());
        var revocation = com.korrali.eudirp.support.AlwaysGoodRevocationChecker.INSTANCE;
        var validator = new DefaultCertificateValidator(trustList, revocation);
        var resolver = new HotReloadingCertificateResolver(certStore, validator);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scenario", "Certificate rotated mid-session");
        result.put("codePath", "HotReloadingCertificateResolver.resolveValid()");

        Map<String, Object> firstAttempt = new LinkedHashMap<>();
        try {
            resolver.resolveValid();
            firstAttempt.put("outcome", "UNEXPECTED: succeeded with the still-expired certificate");
        } catch (ExpiredCertificateException e) {
            firstAttempt.put("outcome", "failed as expected (cached certificate is expired)");
            firstAttempt.put("exceptionType", e.getClass().getSimpleName());
            firstAttempt.put("expiredAt", e.expiredAt().toString());
        }
        result.put("firstAttempt", firstAttempt);

        // Simulate an operator rotating the certificate on disk mid-session.
        DemoCertificateFixtures.IssuedCertificate freshLeaf = DemoCertificateFixtures.leaf(
                ca, "rotating-rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS), null);
        DemoCertificateFixtures.writePkcs12(keystorePath, password, freshLeaf, ca.certificate());
        result.put("rotationEvent", "keystore file on disk overwritten with a freshly-issued certificate "
                + "(serial " + freshLeaf.certificate().getSerialNumber() + "); in-memory cache still holds the old one");

        Map<String, Object> secondAttempt = new LinkedHashMap<>();
        try {
            RpKeyMaterial resolved = resolver.resolveValid();
            secondAttempt.put("outcome", "succeeded on retry via hot reload");
            secondAttempt.put("resolvedCertificateSerial", resolved.leaf().getSerialNumber().toString());
            secondAttempt.put("resolvedCertificateNotAfter", resolved.leaf().getNotAfter().toInstant().toString());
            secondAttempt.put("callerSees", "the request proceeds using the newly-rotated certificate, transparently — "
                    + "the caller that invoked resolveValid() never sees the intermediate failure.");
        } catch (Exception e) {
            secondAttempt.put("outcome", "UNEXPECTED: still failed after rotation: " + e.getMessage());
        }
        result.put("secondAttempt", secondAttempt);

        Files.deleteIfExists(keystorePath);
        Files.deleteIfExists(tempDir);
        return result;
    }
}
