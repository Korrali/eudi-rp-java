package com.korrali.eudirp.presentation;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The wallet's {@code direct_post} Authorization Response: {@code vp_token} keyed by the DCQL
 * credential {@code id}, each value an array of one or more presentation strings (DESIGN.md §1).
 */
public record AuthorizationResponse(Map<String, List<String>> vpToken, String state) {

    /** Parses the {@code vp_token} form parameter's JSON-encoded value plus the {@code state}
     * form parameter, as posted to a {@code response_uri} under {@code response_mode=direct_post}. */
    public static AuthorizationResponse fromDirectPostForm(String vpTokenJson, String state) throws PresentationVerificationException {
        try {
            Map<String, Object> parsed = JSONObjectUtils.parse(vpTokenJson);
            Map<String, List<String>> vpToken = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : parsed.entrySet()) {
                if (!(entry.getValue() instanceof List<?> rawList)) {
                    throw new PresentationVerificationException(
                            "vp_token entry '" + entry.getKey() + "' is not a JSON array");
                }
                vpToken.put(entry.getKey(), rawList.stream().map(Object::toString).toList());
            }
            return new AuthorizationResponse(vpToken, state);
        } catch (ParseException e) {
            throw new PresentationVerificationException("vp_token is not valid JSON: " + e.getMessage(), e);
        }
    }
}
