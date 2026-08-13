package com.korrali.eudirp.presentation;

import java.util.Set;

/**
 * The RP's declared attribute paths, as a flat set of dot-notation strings (e.g.
 * {@code "given_name"}, {@code "address.street_address"}). {@link #claim(String)} is the only way
 * to obtain a {@link DcqlClaimQuery} to put in a request — there is no path that constructs one
 * without going through this check, so requesting an undeclared attribute means deliberately
 * bypassing the type, not a one-line oversight.
 */
public final class DeclaredAttributeSet {

    private final Set<String> declaredPaths;

    public DeclaredAttributeSet(Set<String> declaredPaths) {
        this.declaredPaths = Set.copyOf(declaredPaths);
    }

    public static DeclaredAttributeSet from(RegistrationMetadataProvider provider) {
        return provider.declaredAttributes();
    }

    public DcqlClaimQuery claim(String dotPath) throws UndeclaredAttributeException {
        if (!declaredPaths.contains(dotPath)) {
            throw new UndeclaredAttributeException(dotPath);
        }
        return new DcqlClaimQuery(java.util.List.of(dotPath.split("\\.")));
    }

    public Set<String> declaredPaths() {
        return declaredPaths;
    }
}
