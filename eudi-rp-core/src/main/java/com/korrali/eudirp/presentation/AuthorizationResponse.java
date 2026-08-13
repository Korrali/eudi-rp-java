package com.korrali.eudirp.presentation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The wallet's Authorization Response: {@code vp_token} keyed by the DCQL credential {@code id},
 * each value an array of one or more presentation strings (DESIGN.md §1). Covers both
 * {@code response_mode=direct_post} (plain form fields) and {@code direct_post.jwt} (a single
 * encrypted {@code response} JWE, per OpenID4VP §response_encryption) — either way, verification
 * downstream (see {@link PresentationResponseVerifier}) works against the same normalized shape.
 */
public record AuthorizationResponse(Map<String, List<String>> vpToken, String state) {

    /** Parses the {@code vp_token} form parameter's JSON-encoded value plus the {@code state}
     * form parameter, as posted to a {@code response_uri} under {@code response_mode=direct_post}. */
    public static AuthorizationResponse fromDirectPostForm(String vpTokenJson, String state) throws PresentationVerificationException {
        try {
            Map<String, Object> vpTokenMap = JSONObjectUtils.parse(vpTokenJson);
            return new AuthorizationResponse(parseVpTokenEntries(vpTokenMap), state);
        } catch (ParseException e) {
            throw new PresentationVerificationException("vp_token is not valid JSON: " + e.getMessage(), e);
        }
    }

    /** Decrypts and parses a {@code response_mode=direct_post.jwt} submission: a single compact
     * JWE, decrypted with the private half of the key {@link PresentationRequestBuilder} generated
     * and advertised via {@code client_metadata.jwks} for this request. Per OpenID4VP
     * §response_encryption, the decrypted payload's top-level JSON members ARE the response
     * parameters ({@code vp_token}, {@code state}, ...), not a further-nested object. */
    public static AuthorizationResponse fromDirectPostJwt(String compactJwe, ECKey recipientKey) throws PresentationVerificationException {
        try {
            JWEObject jwe = JWEObject.parse(compactJwe);
            jwe.decrypt(new ECDHDecrypter(recipientKey));
            Map<String, Object> payload = JSONObjectUtils.parse(jwe.getPayload().toString());
            String state = payload.get("state") != null ? payload.get("state").toString() : null;
            if (!(payload.get("vp_token") instanceof Map<?, ?> vpTokenMap)) {
                throw new PresentationVerificationException("Decrypted response has no vp_token object");
            }
            return new AuthorizationResponse(parseVpTokenEntries(vpTokenMap), state);
        } catch (ParseException e) {
            throw new PresentationVerificationException("Encrypted response payload is not valid JSON: " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw new PresentationVerificationException("Failed to decrypt direct_post.jwt response: " + e.getMessage(), e);
        }
    }

    private static Map<String, List<String>> parseVpTokenEntries(Map<?, ?> vpTokenMap) throws PresentationVerificationException {
        Map<String, List<String>> vpToken = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : vpTokenMap.entrySet()) {
            if (!(entry.getValue() instanceof List<?> rawList)) {
                throw new PresentationVerificationException(
                        "vp_token entry '" + entry.getKey() + "' is not a JSON array");
            }
            vpToken.put(entry.getKey().toString(), rawList.stream().map(Object::toString).toList());
        }
        return vpToken;
    }
}
