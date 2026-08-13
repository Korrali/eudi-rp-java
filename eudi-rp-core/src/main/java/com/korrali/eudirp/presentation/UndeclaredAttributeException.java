package com.korrali.eudirp.presentation;

/**
 * Thrown when code tries to build a claim query for an attribute the RP has not declared it
 * intends to request. Requesting undeclared attributes is a compliance violation (eIDAS2 Art.
 * 5b(3); DESIGN.md §2.2) — this exception is the enforcement mechanism, not just documentation of
 * the rule. Checked deliberately (DESIGN.md §5's {@code DeclaredAttributeSet.claim(...)} signature):
 * a caller has to either handle it or explicitly propagate it, so requesting an undeclared
 * attribute cannot happen as a silent one-line oversight.
 */
public final class UndeclaredAttributeException extends Exception {

    public UndeclaredAttributeException(String attributePath) {
        super("Attribute '" + attributePath + "' is not in the declared attribute set; "
                + "requesting it would violate the RP's registered intended use");
    }
}
