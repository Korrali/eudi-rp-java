package com.korrali.eudirp.demo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concurrency check on the demo's request handling: many simultaneous presentation flows must stay
 * isolated from each other — no transaction ID collisions, no cross-contaminated results. The
 * in-memory {@link TransactionStore} is a thin {@code ConcurrentHashMap} wrapper, so the real
 * question isn't the map itself, it's whether the controller logic built on top of it holds up
 * under real concurrent load.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConcurrentPresentationsTest {

    private static final int CONCURRENT_FLOWS = 25;

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

    @Test
    void manySimultaneousPresentationFlowsStayIsolatedAndAllVerify() throws Exception {
        String base = "http://localhost:" + port;
        ExecutorService pool = Executors.newFixedThreadPool(CONCURRENT_FLOWS);
        TestRestTemplate rest = new TestRestTemplate();

        try {
            List<Callable<String>> flows = IntStream.range(0, CONCURRENT_FLOWS)
                    .<Callable<String>>mapToObj(i -> () -> runOneFlow(rest, base))
                    .collect(Collectors.toList());

            List<Future<String>> futures = pool.invokeAll(flows, 60, TimeUnit.SECONDS);
            List<String> transactionIds = futures.stream().map(f -> {
                try {
                    return f.get();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).collect(Collectors.toList());

            assertThat(transactionIds).hasSize(CONCURRENT_FLOWS);
            assertThat(Set.copyOf(transactionIds))
                    .as("every concurrent flow must get a distinct transaction id — no collisions")
                    .hasSize(CONCURRENT_FLOWS);

            for (String transactionId : transactionIds) {
                @SuppressWarnings("unchecked")
                Map<String, Object> status = rest.getForObject(base + "/api/presentations/" + transactionId, Map.class);
                assertThat(status.get("state")).as("transaction %s", transactionId).isEqualTo("VERIFIED");

                @SuppressWarnings("unchecked")
                List<Map<String, Object>> credentials = (List<Map<String, Object>>) status.get("credentials");
                @SuppressWarnings("unchecked")
                Map<String, Object> disclosed = (Map<String, Object>) credentials.get(0).get("disclosedClaims");
                assertThat(disclosed).containsEntry("given_name", "Ada");
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static String runOneFlow(TestRestTemplate rest, String base) {
        @SuppressWarnings("unchecked")
        Map<String, Object> created = rest.postForObject(base + "/api/presentations", null, Map.class);
        String transactionId = (String) created.get("transactionId");

        rest.postForEntity(base + "/api/presentations/" + transactionId + "/simulate-scan", null, Map.class);
        return transactionId;
    }
}
