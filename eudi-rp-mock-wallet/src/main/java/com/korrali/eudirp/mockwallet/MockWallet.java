package com.korrali.eudirp.mockwallet;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Produces valid, spec-shaped OpenID4VP responses to an eudi-rp-core-signed request, so
 * integration tests run without a live wallet (DESIGN.md Phase 4). Not a wallet SDK, not a
 * product surface — test support only.
 *
 * <p>Structural checks only: this class does not perform full chain validation of the RP's
 * presented certificate against a trust list (that machinery is exhaustively tested from the RP's
 * own side in {@code eudi-rp-core}) — it checks the request object is well-typed and parseable, as
 * a real wallet's first gate would.
 */
public final class MockWallet {

    private final KeyPair mockIssuerKeyPair;
    private final String mockIssuer;
    private final Map<String, Object> claimValueOverrides;

    public MockWallet() {
        this(Map.of());
    }

    public MockWallet(Map<String, Object> claimValueOverrides) {
        this.mockIssuerKeyPair = generateKeyPair();
        this.mockIssuer = "https://mock-issuer.eudi-rp-java.test";
        this.claimValueOverrides = claimValueOverrides;
    }

    /**
     * The mock credential issuer's public key, for wiring up an
     * {@code IssuerSignatureVerifierResolver} in tests or the demo app. A real wallet has no
     * equivalent of this method — issuer trust in production comes from configured issuer trust
     * material, never from the wallet itself. This exists purely because a mock needs some way to
     * be independently verifiable without standing up real issuer trust infrastructure.
     */
    public java.security.interfaces.RSAPublicKey issuerPublicKey() {
        return (java.security.interfaces.RSAPublicKey) mockIssuerKeyPair.getPublic();
    }

    public MockWalletResponse respondTo(String requestObjectJwt) throws MockWalletException {
        SignedJWT request = parseAndCheckRequest(requestObjectJwt);

        try {
            JWTClaimsSet claims = request.getJWTClaimsSet();
            String responseUri = claims.getStringClaim("response_uri");
            String state = claims.getStringClaim("state");

            @SuppressWarnings("unchecked")
            Map<String, Object> dcqlQuery = (Map<String, Object>) claims.getClaim("dcql_query");
            if (dcqlQuery == null) {
                throw new MockWalletException("Request object has no dcql_query claim");
            }

            Map<String, Object> vpToken = new LinkedHashMap<>();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> credentialQueries = (List<Map<String, Object>>) dcqlQuery.get("credentials");
            for (Map<String, Object> credentialQuery : credentialQueries) {
                vpToken.put((String) credentialQuery.get("id"), List.of(buildMockPresentation(credentialQuery)));
            }

            String vpTokenJson = toJson(vpToken);
            return new MockWalletResponse(vpTokenJson, state, responseUri);
        } catch (ParseException e) {
            throw new MockWalletException("Failed to read request object claims: " + e.getMessage(), e);
        }
    }

    /** POSTs the response as {@code application/x-www-form-urlencoded}, per {@code response_mode=direct_post}. */
    public HttpResponse<String> postToResponseUri(MockWalletResponse response) throws MockWalletException {
        String form = "vp_token=" + urlEncode(response.vpTokenJson())
                + (response.state() != null ? "&state=" + urlEncode(response.state()) : "");
        HttpRequest httpRequest = HttpRequest.newBuilder(URI.create(response.responseUri()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        try {
            return HttpClient.newHttpClient().send(httpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new MockWalletException("Failed to POST response to " + response.responseUri() + ": " + e.getMessage(), e);
        }
    }

    private SignedJWT parseAndCheckRequest(String requestObjectJwt) throws MockWalletException {
        try {
            SignedJWT jwt = SignedJWT.parse(requestObjectJwt);
            JOSEObjectType type = jwt.getHeader().getType();
            if (type == null || !"oauth-authz-req+jwt".equals(type.toString())) {
                throw new MockWalletException(
                        "Request object 'typ' header must be oauth-authz-req+jwt; a real wallet MUST reject this request");
            }
            if (jwt.getHeader().getX509CertChain() == null || jwt.getHeader().getX509CertChain().isEmpty()) {
                throw new MockWalletException("Request object has no x5c certificate chain header");
            }
            return jwt;
        } catch (ParseException e) {
            throw new MockWalletException("Request object did not parse as a JWS: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private String buildMockPresentation(Map<String, Object> credentialQuery) throws MockWalletException {
        String format = (String) credentialQuery.get("format");
        if (!"dc+sd-jwt".equals(format)) {
            throw new MockWalletException("Mock wallet only supports dc+sd-jwt; requested format was " + format);
        }
        Map<String, Object> meta = (Map<String, Object>) credentialQuery.get("meta");
        List<String> vctValues = meta != null ? (List<String>) meta.get("vct_values") : List.of();
        String vct = vctValues != null && !vctValues.isEmpty() ? vctValues.get(0) : "https://credentials.example.com/mock_credential";

        List<Map<String, Object>> claimQueries = (List<Map<String, Object>>) credentialQuery.get("claims");

        try {
            java.util.List<String> disclosures = new java.util.ArrayList<>();
            java.util.List<String> digests = new java.util.ArrayList<>();
            int salt = 1;
            if (claimQueries != null) {
                for (Map<String, Object> claimQuery : claimQueries) {
                    List<String> path = (List<String>) claimQuery.get("path");
                    String claimName = path.get(path.size() - 1);
                    Object value = mockValueFor(claimName);
                    String disclosureJson = "[\"mock-salt-" + (salt++) + "\",\"" + claimName + "\","
                            + toJson(value) + "]";
                    String disclosureB64 = Base64URL.encode(disclosureJson.getBytes(StandardCharsets.UTF_8)).toString();
                    disclosures.add(disclosureB64);
                    digests.add(sha256(disclosureB64));
                }
            }

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(mockIssuer)
                    .claim("vct", vct)
                    .claim("_sd_alg", "sha-256")
                    .claim("_sd", digests)
                    .build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
            SignedJWT jwt = new SignedJWT(header, claimsSet);
            jwt.sign(new RSASSASigner((RSAPrivateKey) mockIssuerKeyPair.getPrivate()));

            StringBuilder presentation = new StringBuilder(jwt.serialize());
            for (String disclosure : disclosures) {
                presentation.append('~').append(disclosure);
            }
            presentation.append('~');
            return presentation.toString();
        } catch (Exception e) {
            throw new MockWalletException("Failed to build mock presentation: " + e.getMessage(), e);
        }
    }

    private Object mockValueFor(String claimName) {
        if (claimValueOverrides.containsKey(claimName)) {
            return claimValueOverrides.get(claimName);
        }
        return switch (claimName) {
            case "given_name" -> "Ada";
            case "family_name" -> "Lovelace";
            case "birth_date" -> "1990-01-01";
            case "street_address" -> "123 Main St";
            case "locality" -> "Brussels";
            case "postal_code" -> "1000";
            case "country" -> "BE";
            case "nationality" -> "BE";
            default -> "mock-" + claimName;
        };
    }

    private static String toJson(Object value) {
        if (value instanceof String s) {
            return "\"" + s.replace("\"", "\\\"") + "\"";
        }
        if (value instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (var entry : map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(entry.getKey()).append("\":").append(toJson(entry.getValue()));
            }
            return sb.append('}').toString();
        }
        if (value instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(',');
                first = false;
                sb.append(toJson(item));
            }
            return sb.append(']').toString();
        }
        return String.valueOf(value);
    }

    private static String sha256(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.US_ASCII));
            return Base64URL.encode(hash).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
