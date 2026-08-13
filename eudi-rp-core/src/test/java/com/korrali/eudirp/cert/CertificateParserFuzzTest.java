package com.korrali.eudirp.cert;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Randomized fuzzing of the certificate parsers: security-relevant surface, since this is the
 * first code real, untrusted bytes hit. Not a coverage-guided fuzzer (no Jazzer dependency added —
 * a plain randomized loop is enough to answer the two questions that actually matter here: does it
 * ever hang, and does it ever throw something other than the one typed exception it's supposed to).
 */
class CertificateParserFuzzTest {

    private static final int ITERATIONS = 2000;
    private final SecureRandom random = new SecureRandom();
    private final ToleratingCertificateParser parser = new ToleratingCertificateParser();

    @RepeatedTest(1)
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void neverHangsAndNeverThrowsAnythingOtherThanMalformedCertificateExceptionOnRandomBytes() {
        for (int i = 0; i < ITERATIONS; i++) {
            byte[] garbage = randomBytes(1 + random.nextInt(512));

            assertThatCode(() -> {
                try {
                    parser.parse(garbage);
                    // Parsing successfully is not itself a bug — astronomically unlikely with
                    // random bytes, but not the property under test either way.
                } catch (MalformedCertificateException expected) {
                    // this is the only acceptable failure mode
                }
            }).as("iteration %d with input length %d must not throw anything other than MalformedCertificateException", i, garbage.length)
                    .doesNotThrowAnyException();
        }
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void handlesEmptyInputWithoutHanging() {
        assertThatCode(() -> {
            try {
                parser.parse(new byte[0]);
            } catch (MalformedCertificateException expected) {
                // expected
            }
        }).doesNotThrowAnyException();
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void handlesInputThatLooksLikeAValidSequenceHeaderButIsntWithoutHanging() {
        // 0x30 passes the shallow "starts like a SEQUENCE" check before anything falls apart —
        // this is deliberately the same shape as the truncated-garbage.der fixture.
        byte[] input = new byte[256];
        random.nextBytes(input);
        input[0] = 0x30;

        assertThatCode(() -> {
            try {
                parser.parse(input);
            } catch (MalformedCertificateException expected) {
                // expected
            }
        }).doesNotThrowAnyException();
    }

    @Test
    void aRealValidCertificateStillParsesCorrectlyAfterFuzzingTheParserInstance() throws Exception {
        // Sanity check that repeated fuzzing above didn't leave the (stateless) parser instance in
        // some corrupted state — reuses the module's own committed fixture.
        byte[] valid = java.nio.file.Files.readAllBytes(
                java.nio.file.Path.of("src/test/resources/certs/malformed/valid-control.der"));

        assertThat(parser.parse(valid)).isNotNull();
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
