package com.korrali.eudirp.cert;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Exercises the strict/tolerant split against real, committed fixtures (see
 * {@code MalformedCertificateFixtureGenerator}) rather than mocks — the "empty issuer DN"
 * malformation was empirically verified to split this JDK's strict X.509 parser from
 * BouncyCastle's tolerant one; see that generator's javadoc for the other malformations that were
 * tried and did NOT split.
 */
class ToleratingCertificateParserTest {

    private static final Path FIXTURES = Path.of("src/test/resources/certs/malformed");

    private final ToleratingCertificateParser parser = new ToleratingCertificateParser();

    @Test
    void parsesAWellFormedCertificateWithoutEngagingTheFallback() throws Exception {
        byte[] valid = Files.readAllBytes(FIXTURES.resolve("valid-control.der"));

        var certificate = parser.parse(valid);

        assertThat(certificate).isNotNull();
    }

    @Test
    void strictParserAloneRejectsTheEmptyIssuerDnCertificate() throws Exception {
        byte[] malformed = Files.readAllBytes(FIXTURES.resolve("empty-issuer-dn.der"));

        assertThatThrownBy(() -> new StrictCertificateParser().parse(malformed))
                .isInstanceOf(MalformedCertificateException.class);
    }

    @Test
    void tolerantParserAloneAcceptsTheEmptyIssuerDnCertificate() throws Exception {
        byte[] malformed = Files.readAllBytes(FIXTURES.resolve("empty-issuer-dn.der"));

        var certificate = new TolerantCertificateParser().parse(malformed);

        assertThat(certificate).isNotNull();
    }

    @Test
    void compositeParserFallsBackToTolerantPathAndSucceeds() throws Exception {
        byte[] malformed = Files.readAllBytes(FIXTURES.resolve("empty-issuer-dn.der"));

        var certificate = parser.parse(malformed);

        assertThat(certificate).isNotNull();
    }

    @Test
    void bothPathsRejectGenuinelyCorruptBytes() throws Exception {
        byte[] garbage = Files.readAllBytes(FIXTURES.resolve("truncated-garbage.der"));

        assertThatThrownBy(() -> parser.parse(garbage))
                .isInstanceOf(MalformedCertificateException.class)
                .satisfies(e -> assertThat(((MalformedCertificateException) e).tolerantParsePathEngaged()).isTrue());
    }
}
