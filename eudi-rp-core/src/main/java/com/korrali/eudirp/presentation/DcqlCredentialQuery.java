package com.korrali.eudirp.presentation;

import java.util.List;

/**
 * One entry of a DCQL query's {@code credentials} array (OpenID4VP §Digital Credentials Query
 * Language). {@code vctValues} corresponds to {@code meta.vct_values}, required and meaningful
 * only for {@link CredentialFormat#SD_JWT_VC}.
 */
public record DcqlCredentialQuery(
        String id,
        CredentialFormat format,
        List<String> vctValues,
        List<DcqlClaimQuery> claims
) {

    public DcqlCredentialQuery {
        if (format != CredentialFormat.SD_JWT_VC) {
            throw new UnsupportedOperationException(
                    "Only " + CredentialFormat.SD_JWT_VC + " is supported; " + format + " is recognized but not implemented (DESIGN.md §3/§6)");
        }
        vctValues = List.copyOf(vctValues);
        claims = List.copyOf(claims);
    }
}
