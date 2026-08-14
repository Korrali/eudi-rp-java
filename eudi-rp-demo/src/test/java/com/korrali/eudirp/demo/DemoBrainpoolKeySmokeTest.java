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
 * The same full round trip as {@link DemoApplicationSmokeTest}, but with the RP access certificate
 * generated on BrainpoolP256r1 instead of RSA — proves the whole Spring wiring (certificate
 * resolution, request signing, response verification) actually works end-to-end with a curve BSI
 * recommends for German sovereign deployments (ENISA ECCG "Agreed Cryptographic Mechanisms v2.0",
 * Apr 2025, lists it "Recommended", same tier as NIST P-256), not just that
 * {@code PresentationRequestBuilder}'s unit tests pass in isolation.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DemoBrainpoolKeySmokeTest {

    @TempDir
    static Path dataDir;

    @DynamicPropertySource
    static void demoDataDir(DynamicPropertyRegistry registry) throws Exception {
        DemoPkiBootstrap.generateIfMissing(dataDir, "brainpoolP256r1");
        registry.add("eudirp.certificate.keystore-path", () -> dataDir.resolve("rp.p12"));
        registry.add("eudirp.trust-list.path", () -> dataDir.resolve("trust.pem"));
        registry.add("eudirp.registration.declared-attributes-file", () -> dataDir.resolve("declared-attributes.txt"));
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate rest = new TestRestTemplate();

    @Test
    void fullMockWalletRoundTripVerifiesWithABrainpoolRpCertificate() {
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
}
