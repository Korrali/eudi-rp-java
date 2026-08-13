package com.korrali.eudirp.cert.fixtures;

import com.korrali.eudirp.cert.support.TestCertificates;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Manual, one-shot tool (not run by the test suite) that generated the fixtures committed under
 * {@code src/test/resources/certs/malformed/}. Re-run it only if the fixtures need regenerating —
 * key generation is random, so re-running produces different (but equally valid) bytes.
 *
 * <p>Run with: {@code java -cp <test-classpath> com.korrali.eudirp.cert.fixtures.MalformedCertificateFixtureGenerator}
 *
 * <p>{@code empty-issuer-dn.der} is a real, otherwise-valid certificate whose issuer Name has been
 * rewritten to an empty SEQUENCE (zero RDNs) — structurally valid ASN.1, but rejected by the JDK's
 * strict {@code sun.security.x509} parser ("Empty issuer DN not allowed in X509Certificates"),
 * while BouncyCastle's {@code X509CertificateHolder} accepts it. This is the exact class of
 * failure {@link com.korrali.eudirp.cert.ToleratingCertificateParser} exists for.
 *
 * <p>This specific malformation was chosen empirically, not from recall: BER indefinite-length
 * encoding (both at the outer Certificate SEQUENCE and the inner TBSCertificate SEQUENCE) and
 * duplicate critical extensions were tried first and, on this JDK build, did NOT split strict vs.
 * tolerant parsing — indefinite-length BER is now accepted by both, and duplicate extensions are
 * rejected by both. Empty issuer DN is the one that actually reproduces the split; see the git
 * history of this file / project notes for the experiment.
 */
public final class MalformedCertificateFixtureGenerator {

    private MalformedCertificateFixtureGenerator() {
    }

    public static void main(String[] args) throws Exception {
        Path outputDir = Path.of("src/test/resources/certs/malformed");
        Files.createDirectories(outputDir);

        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("eudi-rp-java Test Fixture CA");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "malformed-fixture.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));

        byte[] validDer = leaf.certificate().getEncoded();
        byte[] emptyIssuerDn = TestCertificates.withEmptyIssuerDn(validDer);

        byte[] garbage = new byte[256];
        new SecureRandom().nextBytes(garbage);
        garbage[0] = 0x30; // pass the superficial "looks like a SEQUENCE" check, still garbage past that

        Files.write(outputDir.resolve("valid-control.der"), validDer);
        Files.write(outputDir.resolve("empty-issuer-dn.der"), emptyIssuerDn);
        Files.write(outputDir.resolve("truncated-garbage.der"), garbage);
        Files.writeString(outputDir.resolve("ca.pem"), toPem(ca.certificate().getEncoded()));

        System.out.println("Wrote fixtures to " + outputDir.toAbsolutePath());
    }

    private static String toPem(byte[] der) {
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }
}
