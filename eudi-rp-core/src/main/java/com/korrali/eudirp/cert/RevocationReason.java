package com.korrali.eudirp.cert;

/**
 * Revocation reason codes per RFC 5280 §5.3.1 (CRLReason).
 */
public enum RevocationReason {
    UNSPECIFIED,
    KEY_COMPROMISE,
    CA_COMPROMISE,
    AFFILIATION_CHANGED,
    SUPERSEDED,
    CESSATION_OF_OPERATION,
    CERTIFICATE_HOLD,
    REMOVE_FROM_CRL,
    PRIVILEGE_WITHDRAWN,
    AA_COMPROMISE,
    /** No reason was supplied by the CRL/OCSP responder. */
    NOT_SPECIFIED
}
