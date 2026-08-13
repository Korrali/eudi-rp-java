package com.korrali.eudirp.presentation;

import com.nimbusds.jose.JOSEException;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Verifies a wallet's {@link AuthorizationResponse} against the original {@link SignedPresentationRequest}
 * and the DCQL credential queries that were sent: {@code state} matches, every requested credential
 * id has at least one presentation, each presentation's issuer signature verifies (via the supplied
 * {@link IssuerSignatureVerifierResolver}), and disclosed claims are resolved (DESIGN.md §1).
 */
public final class PresentationResponseVerifier {

    private final IssuerSignatureVerifierResolver issuerSignatureVerifierResolver;

    public PresentationResponseVerifier(IssuerSignatureVerifierResolver issuerSignatureVerifierResolver) {
        this.issuerSignatureVerifierResolver = issuerSignatureVerifierResolver;
    }

    public List<VerifiedPresentation> verify(AuthorizationResponse response, SignedPresentationRequest originalRequest,
                                              List<DcqlCredentialQuery> queries) throws PresentationVerificationException {
        if (!Objects.equals(response.state(), originalRequest.state())) {
            throw new PresentationVerificationException("state in response does not match the original request");
        }

        List<VerifiedPresentation> results = new ArrayList<>();
        for (DcqlCredentialQuery query : queries) {
            List<String> presentations = response.vpToken().get(query.id());
            if (presentations == null || presentations.isEmpty()) {
                throw new PresentationVerificationException(
                        "No presentation returned for requested credential id '" + query.id() + "'");
            }
            for (String presentation : presentations) {
                results.add(verifyOne(presentation, query));
            }
        }
        return results;
    }

    private VerifiedPresentation verifyOne(String presentation, DcqlCredentialQuery query) throws PresentationVerificationException {
        SdJwtVc sdJwtVc = SdJwtVc.parse(presentation);

        try {
            var verifier = issuerSignatureVerifierResolver.resolve(sdJwtVc.issuerSignedJwt());
            if (!sdJwtVc.issuerSignedJwt().verify(verifier)) {
                throw new PresentationVerificationException(
                        "Issuer signature did not verify for credential '" + query.id() + "'");
            }
        } catch (JOSEException e) {
            throw new PresentationVerificationException(
                    "Issuer signature verification failed for credential '" + query.id() + "': " + e.getMessage(), e);
        }

        var disclosedClaims = sdJwtVc.resolveDisclosedClaims();
        Object vct = disclosedClaims.get("vct");
        if (vct != null && !query.vctValues().isEmpty() && !query.vctValues().contains(vct.toString())) {
            throw new PresentationVerificationException(
                    "Credential '" + query.id() + "' has vct '" + vct + "' which was not one of the requested values " + query.vctValues());
        }

        return new VerifiedPresentation(query.id(), CredentialFormat.SD_JWT_VC, disclosedClaims);
    }
}
