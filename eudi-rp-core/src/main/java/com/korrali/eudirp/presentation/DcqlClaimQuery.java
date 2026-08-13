package com.korrali.eudirp.presentation;

import java.util.List;

/** One entry of a DCQL Credential Query's {@code claims} array: a claim path, e.g.
 * {@code ["address", "street_address"]} (OpenID4VP §Claims Path Pointer). */
public record DcqlClaimQuery(List<String> path) {

    public DcqlClaimQuery {
        path = List.copyOf(path);
    }

    public static DcqlClaimQuery of(String... pathSegments) {
        return new DcqlClaimQuery(List.of(pathSegments));
    }

    /** The dot-joined form used as the key in {@link DeclaredAttributeSet}, e.g. {@code address.street_address}. */
    public String dotPath() {
        return String.join(".", path);
    }
}
