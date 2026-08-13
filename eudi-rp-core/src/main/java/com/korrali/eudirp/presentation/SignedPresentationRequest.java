package com.korrali.eudirp.presentation;

/**
 * A signed OpenID4VP authorization Request Object (RFC 9101 JAR) ready to be delivered to a
 * wallet, plus the parameters needed alongside it to build the request URI / QR payload.
 */
public record SignedPresentationRequest(
        String requestObjectJwt,
        String clientId,
        String nonce,
        String state,
        String responseUri,
        ResponseMode responseMode
) {
}
