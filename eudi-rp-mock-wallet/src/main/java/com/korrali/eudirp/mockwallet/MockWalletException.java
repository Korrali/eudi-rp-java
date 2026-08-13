package com.korrali.eudirp.mockwallet;

/** The mock wallet could not process a request (malformed request object, unsupported format). */
public final class MockWalletException extends Exception {

    public MockWalletException(String message) {
        super(message);
    }

    public MockWalletException(String message, Throwable cause) {
        super(message, cause);
    }
}
