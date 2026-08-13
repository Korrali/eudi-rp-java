package com.korrali.eudirp.presentation;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;

/**
 * Resolves the {@link JWSVerifier} for a credential issuer's signature on an SD-JWT VC.
 *
 * <p>Deliberately left as a caller-supplied strategy rather than a named "provider" in the
 * DESIGN.md §4 sense: credential-issuer trust (which CAs/issuers a wallet's presented credential
 * should be trusted from) is a different trust domain from the RP's own access-certificate trust
 * list, and it was not part of what Phase 0 research covered (that was scoped to RP certificate
 * lifecycle — see DESIGN.md §0). Configuring this is the caller's responsibility.
 */
@FunctionalInterface
public interface IssuerSignatureVerifierResolver {

    JWSVerifier resolve(SignedJWT issuerSignedJwt) throws PresentationVerificationException;
}
