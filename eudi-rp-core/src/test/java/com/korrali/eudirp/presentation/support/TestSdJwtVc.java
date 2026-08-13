package com.korrali.eudirp.presentation.support;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builds a real, signed SD-JWT VC presentation string for tests — not a mock of the format. */
public final class TestSdJwtVc {

    private TestSdJwtVc() {
    }

    public record ClaimToDisclose(String name, Object value) {
    }

    public static String build(RSAPrivateKey issuerKey, String issuer, String vct, List<ClaimToDisclose> claims) throws Exception {
        List<String> disclosures = new ArrayList<>();
        List<String> digests = new ArrayList<>();
        int salt = 1;
        for (ClaimToDisclose claim : claims) {
            String disclosureJson = "[\"salt-" + (salt++) + "\",\"" + claim.name() + "\","
                    + toJsonValue(claim.value()) + "]";
            String disclosureB64 = Base64URL.encode(disclosureJson.getBytes(StandardCharsets.UTF_8)).toString();
            disclosures.add(disclosureB64);
            digests.add(sha256(disclosureB64));
        }

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vct", vct)
                .claim("_sd_alg", "sha-256")
                .claim("_sd", digests);
        JWTClaimsSet claimsSet = claimsBuilder.build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(com.nimbusds.jose.JOSEObjectType.JWT).build();
        SignedJWT jwt = new SignedJWT(header, claimsSet);
        jwt.sign(new RSASSASigner(issuerKey));

        StringBuilder presentation = new StringBuilder(jwt.serialize());
        for (String disclosure : disclosures) {
            presentation.append('~').append(disclosure);
        }
        presentation.append('~'); // no key-binding JWT
        return presentation.toString();
    }

    private static String toJsonValue(Object value) {
        if (value instanceof String s) {
            return "\"" + s.replace("\"", "\\\"") + "\"";
        }
        return String.valueOf(value);
    }

    private static String sha256(String input) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.US_ASCII));
        return Base64URL.encode(hash).toString();
    }
}
