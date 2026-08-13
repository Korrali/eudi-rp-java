package com.korrali.eudirp.presentation;

/**
 * Defense-in-depth check at {@link PresentationRequestBuilder#build()} time: even though
 * {@link DeclaredAttributeSet#claim(String)} is the normal way to obtain a {@link DcqlClaimQuery},
 * nothing stops a caller from constructing one directly via {@link DcqlClaimQuery#of}. The builder
 * re-checks every claim against the declared set before signing, so bypassing the type at
 * construction time still gets caught before a request ever leaves the process.
 */
public final class DeclaredScopeViolationException extends Exception {

    public DeclaredScopeViolationException(String attributePath) {
        super("Request includes attribute '" + attributePath + "', which is not in the declared attribute set");
    }
}
