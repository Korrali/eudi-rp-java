package com.korrali.eudirp.cert;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Default {@link TrustListProvider}: reads one or more PEM files (a single bundle, or every
 * {@code .pem}/{@code .crt} file in a directory) from local disk. No network fetch, no scheduled
 * refresh — call {@link #reload()} explicitly if the files on disk changed. See DESIGN.md §4.
 */
public final class LocalFileTrustListProvider implements TrustListProvider {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final Path source;
    private volatile List<X509Certificate> anchors;
    private volatile Instant lastRefreshed;

    public LocalFileTrustListProvider(Path source) {
        this.source = source;
        reload();
    }

    @Override
    public List<X509Certificate> trustAnchors() {
        return anchors;
    }

    @Override
    public Instant lastRefreshed() {
        return lastRefreshed;
    }

    /** Re-reads {@link #source} from disk. */
    public synchronized void reload() {
        try {
            List<Path> files = Files.isDirectory(source)
                    ? listPemFiles(source)
                    : List.of(source);

            List<X509Certificate> loaded = new ArrayList<>();
            for (Path file : files) {
                loaded.addAll(parsePemBundle(file));
            }
            this.anchors = List.copyOf(loaded);
            this.lastRefreshed = Instant.now();
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("Failed to load trust list from " + source, e);
        }
    }

    private static List<Path> listPemFiles(Path dir) throws IOException {
        try (Stream<Path> paths = Files.list(dir)) {
            return paths
                    .filter(p -> p.toString().endsWith(".pem") || p.toString().endsWith(".crt"))
                    .sorted()
                    .toList();
        }
    }

    private static List<X509Certificate> parsePemBundle(Path file) throws IOException, CertificateException {
        List<X509Certificate> certs = new ArrayList<>();
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8);
             PemReader pemReader = new PemReader(reader)) {
            PemObject pemObject;
            while ((pemObject = pemReader.readPemObject()) != null) {
                X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());
                certs.add(new JcaX509CertificateConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getCertificate(holder));
            }
        }
        return certs;
    }
}
