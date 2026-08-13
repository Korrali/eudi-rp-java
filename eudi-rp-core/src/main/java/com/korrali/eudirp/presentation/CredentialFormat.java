package com.korrali.eudirp.presentation;

/**
 * The two DCQL credential format identifiers a Credential Query can name (OpenID4VP §Digital
 * Credentials Query Language). Only {@link #SD_JWT_VC} is implemented — see DESIGN.md §3:
 * mdoc is out of scope, full stop, not a future step. {@link #MSO_MDOC} is recognized here only
 * so a query naming it fails with a clear, typed error instead of being silently mishandled.
 */
public enum CredentialFormat {

    /** {@code dc+sd-jwt} — implemented. */
    SD_JWT_VC("dc+sd-jwt"),
    /** {@code mso_mdoc} — recognized only; always rejected. Not supported. See DESIGN.md §3/§6. */
    MSO_MDOC("mso_mdoc");

    private final String dcqlFormatId;

    CredentialFormat(String dcqlFormatId) {
        this.dcqlFormatId = dcqlFormatId;
    }

    public String dcqlFormatId() {
        return dcqlFormatId;
    }

    public static CredentialFormat fromDcqlFormatId(String id) {
        for (CredentialFormat format : values()) {
            if (format.dcqlFormatId.equals(id)) {
                return format;
            }
        }
        throw new IllegalArgumentException("Unrecognized DCQL format identifier: " + id);
    }
}
