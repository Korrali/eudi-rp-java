package com.korrali.eudirp.demo;

import com.korrali.eudirp.presentation.DcqlCredentialQuery;
import com.korrali.eudirp.presentation.SignedPresentationRequest;
import com.korrali.eudirp.presentation.VerifiedPresentation;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/** In-memory presentation transaction — a real deployment would use a real store; this is a demo. */
public final class Transaction {

    public enum State {
        AWAITING_SCAN, REQUEST_SENT, RESPONSE_RECEIVED, VERIFIED, FAILED
    }

    public final String id;
    public final SignedPresentationRequest signedRequest;
    public final List<DcqlCredentialQuery> queries;
    public final Instant createdAt = Instant.now();
    public final String rpCertificateIssuer;
    public final boolean revocationCheckAttempted;
    public final String revocationCheckOutcome;

    public final AtomicReference<State> state = new AtomicReference<>(State.AWAITING_SCAN);
    public volatile String rawResponseJson;
    public volatile List<VerifiedPresentation> result;
    public volatile String errorType;
    public volatile String errorMessage;
    /** Set only on the direct_post.jwt (conformance-suite) path: the transport was decrypted and
     * the credential was structurally parsed, but the issuer's own signature was NOT verified —
     * this build has no trust configured for arbitrary external test issuers (DESIGN.md's
     * credential-issuer trust boundary). Distinguishing this from the mock-wallet path's full
     * verification, rather than quietly reporting the same "VERIFIED" for both. */
    public volatile String issuerSignatureNote;

    public Transaction(String id, SignedPresentationRequest signedRequest, List<DcqlCredentialQuery> queries,
                        String rpCertificateIssuer, boolean revocationCheckAttempted, String revocationCheckOutcome) {
        this.id = id;
        this.signedRequest = signedRequest;
        this.queries = queries;
        this.rpCertificateIssuer = rpCertificateIssuer;
        this.revocationCheckAttempted = revocationCheckAttempted;
        this.revocationCheckOutcome = revocationCheckOutcome;
    }
}
