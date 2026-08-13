package com.korrali.eudirp.presentation;

import java.util.Map;

/** One successfully-verified credential presentation, resolved from the wallet's {@code vp_token}. */
public record VerifiedPresentation(String credentialId, CredentialFormat format, Map<String, Object> disclosedClaims) {
}
