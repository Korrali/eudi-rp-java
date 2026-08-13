package com.korrali.eudirp.presentation;

import com.korrali.eudirp.cert.RpKeyMaterial;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds and signs an OpenID4VP authorization request per DESIGN.md §1: {@code response_type=vp_token},
 * a DCQL query, {@code client_id} using the {@code x509_hash} scheme (DESIGN.md §2.1), signed as a
 * Request Object (RFC 9101) with {@code typ=oauth-authz-req+jwt} and the RP's certificate chain in
 * the {@code x5c} header.
 *
 * <p>Declared-scope enforcement happens twice: once when a caller obtains each
 * {@link DcqlClaimQuery} via {@link DeclaredAttributeSet#claim(String)}, and again, defensively,
 * here in {@link #build()} — see {@link DeclaredScopeViolationException}.
 */
public final class PresentationRequestBuilder {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RpKeyMaterial signingMaterial;
    private final DeclaredAttributeSet declaredAttributes;
    private final List<DcqlCredentialQuery> credentials = new ArrayList<>();
    private final String nonce = generateNonce();

    private ResponseMode responseMode = ResponseMode.DIRECT_POST;
    private String responseUri;
    private String state;

    public PresentationRequestBuilder(RpKeyMaterial signingMaterial, DeclaredAttributeSet declaredAttributes) {
        this.signingMaterial = signingMaterial;
        this.declaredAttributes = declaredAttributes;
    }

    public PresentationRequestBuilder credential(DcqlCredentialQuery query) {
        credentials.add(query);
        return this;
    }

    public PresentationRequestBuilder responseMode(ResponseMode mode) {
        this.responseMode = mode;
        return this;
    }

    public PresentationRequestBuilder responseUri(String uri) {
        this.responseUri = uri;
        return this;
    }

    public PresentationRequestBuilder state(String state) {
        this.state = state;
        return this;
    }

    public SignedPresentationRequest build() throws DeclaredScopeViolationException, JOSEException, CertificateEncodingException {
        if (responseUri == null) {
            throw new IllegalStateException("responseUri is required for response_mode=" + responseMode.wireValue());
        }
        if (credentials.isEmpty()) {
            throw new IllegalStateException("At least one credential query is required");
        }
        enforceDeclaredScope();

        String clientId = X509HashClientId.compute(signingMaterial.leaf());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("response_type", "vp_token")
                .claim("client_id", clientId)
                .claim("dcql_query", toDcqlQueryObject())
                .claim("nonce", nonce)
                .claim("response_mode", responseMode.wireValue())
                .claim("response_uri", responseUri)
                .claim("state", state)
                .build();

        JWSHeader header = new JWSHeader.Builder(signingAlgorithm())
                .type(new com.nimbusds.jose.JOSEObjectType("oauth-authz-req+jwt"))
                .x509CertChain(certificateChainBase64())
                .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(signer());

        return new SignedPresentationRequest(
                signedJwt.serialize(), clientId, nonce, state, responseUri, responseMode);
    }

    private void enforceDeclaredScope() throws DeclaredScopeViolationException {
        for (DcqlCredentialQuery credential : credentials) {
            for (DcqlClaimQuery claim : credential.claims()) {
                if (!declaredAttributes.declaredPaths().contains(claim.dotPath())) {
                    throw new DeclaredScopeViolationException(claim.dotPath());
                }
            }
        }
    }

    private Map<String, Object> toDcqlQueryObject() {
        List<Object> credentialObjects = new ArrayList<>();
        for (DcqlCredentialQuery credential : credentials) {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("vct_values", credential.vctValues());

            List<Object> claimObjects = new ArrayList<>();
            for (DcqlClaimQuery claim : credential.claims()) {
                claimObjects.add(Map.of("path", claim.path()));
            }

            Map<String, Object> credentialObject = new LinkedHashMap<>();
            credentialObject.put("id", credential.id());
            credentialObject.put("format", credential.format().dcqlFormatId());
            credentialObject.put("meta", meta);
            credentialObject.put("claims", claimObjects);
            credentialObjects.add(credentialObject);
        }
        return Map.of("credentials", credentialObjects);
    }

    private List<Base64> certificateChainBase64() throws CertificateEncodingException {
        List<Base64> chain = new ArrayList<>();
        chain.add(Base64.encode(signingMaterial.leaf().getEncoded()));
        for (var intermediate : signingMaterial.chain()) {
            chain.add(Base64.encode(intermediate.getEncoded()));
        }
        return chain;
    }

    private JWSAlgorithm signingAlgorithm() {
        if (signingMaterial.privateKey() instanceof ECPrivateKey) {
            return JWSAlgorithm.ES256;
        }
        if (signingMaterial.privateKey() instanceof RSAPrivateKey) {
            return JWSAlgorithm.RS256;
        }
        throw new IllegalStateException(
                "Unsupported signing key type: " + signingMaterial.privateKey().getAlgorithm()
                        + " (only RSA and EC keys are supported)");
    }

    private JWSSigner signer() throws JOSEException {
        if (signingMaterial.privateKey() instanceof ECPrivateKey ecKey) {
            return new ECDSASigner(ecKey);
        }
        if (signingMaterial.privateKey() instanceof RSAPrivateKey rsaKey) {
            return new RSASSASigner(rsaKey);
        }
        throw new IllegalStateException(
                "Unsupported signing key type: " + signingMaterial.privateKey().getAlgorithm());
    }

    private static String generateNonce() {
        byte[] bytes = new byte[16]; // 128 bits, per OpenID4VP's nonce entropy requirement
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.encode(bytes).toString();
    }
}
