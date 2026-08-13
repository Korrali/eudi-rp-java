package com.korrali.eudirp.mockwallet;

/** What the mock wallet produced, and where it would be POSTed under {@code response_mode=direct_post}. */
public record MockWalletResponse(String vpTokenJson, String state, String responseUri) {
}
