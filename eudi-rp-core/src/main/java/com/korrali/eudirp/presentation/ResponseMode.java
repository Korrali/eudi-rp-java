package com.korrali.eudirp.presentation;

/**
 * OpenID4VP {@code response_mode} values this library supports for the cross-device (QR) and
 * same-device redirect flows this library targets (DESIGN.md §1). {@code fragment} — the
 * same-device default — is out of scope; see DESIGN.md §6.
 */
public enum ResponseMode {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt");

    private final String wireValue;

    ResponseMode(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }
}
