package com.korrali.eudirp.presentation;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Structural parsing of an SD-JWT VC presentation string: {@code <Issuer-signed JWT>~<Disclosure
 * 1>~...~<Disclosure N>~[<Key Binding JWT>]} (IETF SD-JWT / SD-JWT VC). Resolves top-level
 * selective disclosures by matching each disclosure's digest against the JWT payload's {@code _sd}
 * array.
 *
 * <p><b>Known limitation, stated rather than silently handled:</b> only top-level object-property
 * disclosures are resolved. Nested selective disclosure (an already-disclosed object or array
 * itself containing its own {@code _sd} array) is not implemented in v0.1 and such claims are left
 * undisclosed in the result. Credential-issuer trust (which key verifies the issuer-signed JWT) is
 * out of the scope DESIGN.md's Phase 0 research covered — this class hands signature verification
 * to a caller-supplied {@link com.nimbusds.jose.JWSVerifier} rather than assuming a trust source.
 */
public final class SdJwtVc {

    private final SignedJWT issuerSignedJwt;
    private final List<String> disclosures;

    private SdJwtVc(SignedJWT issuerSignedJwt, List<String> disclosures) {
        this.issuerSignedJwt = issuerSignedJwt;
        this.disclosures = disclosures;
    }

    public static SdJwtVc parse(String presentation) throws PresentationVerificationException {
        String[] parts = presentation.split("~", -1);
        if (parts.length < 1 || parts[0].isEmpty()) {
            throw new PresentationVerificationException("Not a well-formed SD-JWT VC presentation (missing issuer-signed JWT)");
        }
        try {
            SignedJWT jwt = SignedJWT.parse(parts[0]);
            List<String> disclosures = new ArrayList<>();
            // parts[1..] are disclosures, possibly followed by a trailing empty string (no KB-JWT)
            // or a non-empty, non-base64url-JSON-array final segment (a KB-JWT) — KB-JWT is not
            // consumed here since verifying key binding isn't part of this v0.1 scope.
            for (int i = 1; i < parts.length; i++) {
                if (!parts[i].isEmpty()) {
                    disclosures.add(parts[i]);
                }
            }
            return new SdJwtVc(jwt, disclosures);
        } catch (ParseException e) {
            throw new PresentationVerificationException("Issuer-signed JWT segment did not parse: " + e.getMessage(), e);
        }
    }

    public SignedJWT issuerSignedJwt() {
        return issuerSignedJwt;
    }

    /** Resolves top-level disclosed claims by digest-matching against the JWT payload's {@code _sd}
     * array, plus any claims that were never selectively-disclosed to begin with (present directly
     * in the payload). */
    public Map<String, Object> resolveDisclosedClaims() throws PresentationVerificationException {
        try {
            Map<String, Object> payload = issuerSignedJwt.getJWTClaimsSet().getClaims();
            String hashAlgorithm = payload.containsKey("_sd_alg") ? payload.get("_sd_alg").toString() : "sha-256";

            List<?> sdDigests = payload.get("_sd") instanceof List<?> l ? l : List.of();
            java.util.Set<String> digestSet = new java.util.HashSet<>();
            for (Object digest : sdDigests) {
                digestSet.add(digest.toString());
            }

            Map<String, Object> resolved = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                if (entry.getKey().equals("_sd") || entry.getKey().equals("_sd_alg") || entry.getKey().equals("cnf")) {
                    continue;
                }
                resolved.put(entry.getKey(), entry.getValue());
            }

            for (String disclosure : disclosures) {
                String digest = digest(disclosure, hashAlgorithm);
                if (!digestSet.contains(digest)) {
                    continue; // disclosure not referenced by this credential's _sd array — ignore
                }
                List<Object> decoded = decodeDisclosure(disclosure);
                if (decoded.size() == 3) { // [salt, claimName, claimValue] — object property disclosure
                    resolved.put(decoded.get(1).toString(), decoded.get(2));
                }
                // 2-element disclosures ([salt, value]) are array-element disclosures — nested
                // resolution isn't implemented (see class javadoc), so they're not merged in here.
            }
            return resolved;
        } catch (ParseException e) {
            throw new PresentationVerificationException("Failed to read issuer JWT claims: " + e.getMessage(), e);
        }
    }

    private static List<Object> decodeDisclosure(String disclosureBase64Url) throws PresentationVerificationException {
        try {
            byte[] decoded = Base64URL.from(disclosureBase64Url).decode();
            String json = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
            // JSONObjectUtils only parses top-level JSON objects; a disclosure is a top-level JSON
            // array, so it's wrapped in an object to stay within Nimbus's supported public API
            // rather than reaching for its shaded/transitive JSON library directly.
            Map<String, Object> wrapped = JSONObjectUtils.parse("{\"d\":" + json + "}");
            return new ArrayList<>(JSONObjectUtils.getJSONArray(wrapped, "d"));
        } catch (ParseException e) {
            throw new PresentationVerificationException("Failed to decode disclosure: " + e.getMessage(), e);
        }
    }

    private static String digest(String disclosureBase64Url, String hashAlgorithm) throws PresentationVerificationException {
        String javaAlgorithm = switch (hashAlgorithm) {
            case "sha-256" -> "SHA-256";
            case "sha-384" -> "SHA-384";
            case "sha-512" -> "SHA-512";
            default -> throw new PresentationVerificationException("Unsupported SD-JWT hash algorithm: " + hashAlgorithm);
        };
        try {
            MessageDigest md = MessageDigest.getInstance(javaAlgorithm);
            byte[] hash = md.digest(disclosureBase64Url.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return Base64URL.encode(hash).toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(javaAlgorithm + " is a required JDK algorithm", e);
        }
    }
}
