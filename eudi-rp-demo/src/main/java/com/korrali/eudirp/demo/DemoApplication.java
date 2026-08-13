package com.korrali.eudirp.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.file.Path;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) throws Exception {
        String dataDir = System.getProperty("eudirp.demo.data-dir", System.getenv().getOrDefault("EUDIRP_DEMO_DATA_DIR", "./demo-data"));
        DemoPkiBootstrap.generateIfMissing(Path.of(dataDir));
        SpringApplication.run(DemoApplication.class, args);
    }
}
