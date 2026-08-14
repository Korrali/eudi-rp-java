package com.korrali.eudirp.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.file.Path;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) throws Exception {
        String dataDir = System.getProperty("eudirp.demo.data-dir", System.getenv().getOrDefault("EUDIRP_DEMO_DATA_DIR", "./demo-data"));
        // "RSA" (default), or a JCA/BouncyCastle EC curve name: "secp256r1", "brainpoolP256r1",
        // "brainpoolP384r1", etc. — see DemoPkiBootstrap.generateIfMissing. Only takes effect on a
        // fresh demo-data directory; it does not migrate an already-generated keystore.
        String keyAlgorithm = System.getProperty("eudirp.demo.key-algorithm",
                System.getenv().getOrDefault("EUDIRP_DEMO_KEY_ALGORITHM", "RSA"));
        DemoPkiBootstrap.generateIfMissing(Path.of(dataDir), keyAlgorithm);
        SpringApplication.run(DemoApplication.class, args);
    }
}
