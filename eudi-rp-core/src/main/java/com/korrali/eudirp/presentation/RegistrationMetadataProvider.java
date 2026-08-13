package com.korrali.eudirp.presentation;

/**
 * Supplies the RP's own declared attribute set. See DESIGN.md §4 — deliberately thin: models only
 * a flat declared-attribute list, not registrar API shapes or registration-certificate structure,
 * because that part of the spec (CIR 2025/848, ARF's registration chapter) was still mid-revision
 * as of the primary source read for DESIGN.md §0. Only a local, static-config default ships here.
 */
public interface RegistrationMetadataProvider {

    DeclaredAttributeSet declaredAttributes();
}
