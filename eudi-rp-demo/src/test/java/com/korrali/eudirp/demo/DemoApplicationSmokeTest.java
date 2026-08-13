package com.korrali.eudirp.demo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The same round trip verified manually via curl during development, automated: create a
 * presentation, simulate a wallet scan, confirm it verifies — plus one failure-simulator endpoint,
 * as a regression check that the demo backend actually wires up against the real starter.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DemoApplicationSmokeTest {

    @TempDir
    static Path dataDir;

    @DynamicPropertySource
    static void demoDataDir(DynamicPropertyRegistry registry) throws Exception {
        DemoPkiBootstrap.generateIfMissing(dataDir);
        registry.add("eudirp.certificate.keystore-path", () -> dataDir.resolve("rp.p12"));
        registry.add("eudirp.trust-list.path", () -> dataDir.resolve("trust.pem"));
        registry.add("eudirp.registration.declared-attributes-file", () -> dataDir.resolve("declared-attributes.txt"));
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate rest = new TestRestTemplate();

    @Test
    void fullMockWalletRoundTripVerifies() {
        String base = "http://localhost:" + port;

        @SuppressWarnings("unchecked")
        Map<String, Object> created = rest.postForObject(base + "/api/presentations", null, Map.class);
        String transactionId = (String) created.get("transactionId");
        assertThat(transactionId).isNotBlank();

        rest.postForEntity(base + "/api/presentations/" + transactionId + "/simulate-scan", null, Map.class);

        @SuppressWarnings("unchecked")
        Map<String, Object> status = rest.getForObject(base + "/api/presentations/" + transactionId, Map.class);
        assertThat(status.get("state")).isEqualTo("VERIFIED");
    }

    @Test
    void expiredCertificateSimulatorReportsTheTypedException() {
        String base = "http://localhost:" + port;

        @SuppressWarnings("unchecked")
        Map<String, Object> result = rest.postForObject(base + "/api/simulate/expired-certificate", null, Map.class);

        assertThat(result.get("exceptionType")).isEqualTo("ExpiredCertificateException");
    }

    @Test
    void revokedCertificateSimulatorReportsCrlAsTheCatchingSource() {
        String base = "http://localhost:" + port;

        @SuppressWarnings("unchecked")
        Map<String, Object> result = rest.postForObject(base + "/api/simulate/revoked-certificate", null, Map.class);

        assertThat(result.get("outcome")).asString().startsWith("revoked");
        assertThat(result.get("revocationSource")).isEqualTo("CRL");
        assertThat(result.get("reason")).isEqualTo("KEY_COMPROMISE");
        assertThat(result.get("revokedAt")).isNotNull();
    }

    @Test
    void malformedCertificateSimulatorShowsStrictRejectingAndTolerantAccepting() {
        String base = "http://localhost:" + port;

        @SuppressWarnings("unchecked")
        Map<String, Object> result = rest.postForObject(base + "/api/simulate/malformed-certificate", null, Map.class);

        assertThat(result.get("strictPathResult")).isEqualTo("rejected");
        assertThat(result.get("tolerantPathResult")).isEqualTo("accepted");
        assertThat(result.get("outcome")).asString().contains("tolerant fallback");
        assertThat(result.get("parsedSubject")).asString().contains("malformed-rp.example.org");
    }

    @Test
    void certificateRotationSimulatorFailsThenSucceedsOnRetry() {
        String base = "http://localhost:" + port;

        @SuppressWarnings("unchecked")
        Map<String, Object> result = rest.postForObject(base + "/api/simulate/certificate-rotation", null, Map.class);

        @SuppressWarnings("unchecked")
        Map<String, Object> firstAttempt = (Map<String, Object>) result.get("firstAttempt");
        assertThat(firstAttempt.get("exceptionType")).isEqualTo("ExpiredCertificateException");

        @SuppressWarnings("unchecked")
        Map<String, Object> secondAttempt = (Map<String, Object>) result.get("secondAttempt");
        assertThat(secondAttempt.get("outcome")).asString().contains("succeeded on retry");
        assertThat(secondAttempt.get("resolvedCertificateSerial")).isNotNull();
    }
}
