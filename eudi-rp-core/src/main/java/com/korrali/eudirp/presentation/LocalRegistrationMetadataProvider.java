package com.korrali.eudirp.presentation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Default {@link RegistrationMetadataProvider}: reads one declared attribute path per line from a
 * local text file (blank lines and lines starting with {@code #} ignored). No live registrar API
 * call — see DESIGN.md §4.
 *
 * <p>Example file content:
 * <pre>{@code
 * # attributes this RP has registered to request
 * given_name
 * family_name
 * address.street_address
 * }</pre>
 */
public final class LocalRegistrationMetadataProvider implements RegistrationMetadataProvider {

    private final DeclaredAttributeSet declaredAttributes;

    public LocalRegistrationMetadataProvider(Path declaredAttributesFile) {
        this.declaredAttributes = new DeclaredAttributeSet(readPaths(declaredAttributesFile));
    }

    @Override
    public DeclaredAttributeSet declaredAttributes() {
        return declaredAttributes;
    }

    private static Set<String> readPaths(Path file) {
        try {
            Set<String> paths = new LinkedHashSet<>();
            for (String line : Files.readAllLines(file)) {
                String trimmed = line.strip();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                paths.add(trimmed);
            }
            return paths;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read declared attributes from " + file, e);
        }
    }
}
