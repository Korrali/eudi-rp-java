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
}
