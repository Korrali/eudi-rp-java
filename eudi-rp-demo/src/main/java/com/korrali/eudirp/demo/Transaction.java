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
