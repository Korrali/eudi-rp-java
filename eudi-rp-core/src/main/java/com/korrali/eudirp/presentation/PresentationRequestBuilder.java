package com.korrali.eudirp.presentation;

import com.korrali.eudirp.cert.RpKeyMaterial;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .claim("response_type", "vp_token")
                .claim("client_id", clientId)
                .claim("dcql_query", toDcqlQueryObject())
                .claim("nonce", nonce)
                .claim("response_mode", responseMode.wireValue())
                .claim("response_uri", responseUri)
                .claim("state", state)
                // OpenID4VP "aud of a Request Object": MUST be the Wallet Metadata issuer under
                // Dynamic Discovery, or this fixed value under Static Discovery — this library
                // does no dynamic wallet-metadata discovery, so it's always the static case.
                .claim("aud", "https://self-issued.me/v2");

        ECKey responseEncryptionKey = null;
        if (responseMode == ResponseMode.DIRECT_POST_JWT) {
            responseEncryptionKey = generateResponseEncryptionKey();
        }
        claimsBuilder.claim("client_metadata", clientMetadataFor(responseEncryptionKey));
        JWTClaimsSet claims = claimsBuilder.build();

        JWSHeader header = new JWSHeader.Builder(signingAlgorithm())
                .type(new com.nimbusds.jose.JOSEObjectType("oauth-authz-req+jwt"))
                .x509CertChain(certificateChainBase64())
                .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(signer());

        return new SignedPresentationRequest(
                signedJwt.serialize(), clientId, nonce, state, responseUri, responseMode, responseEncryptionKey);
    }

    private static ECKey generateResponseEncryptionKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.ECDH_ES)
                .keyID(UUID.randomUUID().toString())
                .generate();
    }

    private static Map<String, Object> clientMetadataFor(ECKey responseEncryptionKey) {
        Map<String, Object> clientMetadata = new LinkedHashMap<>();
        // REQUIRED whenever not available to the wallet another way (OpenID4VP §new_parameters) —
        // this library only implements SD-JWT VC, so it only ever declares that one format.
        clientMetadata.put("vp_formats_supported", Map.of(
                CredentialFormat.SD_JWT_VC.dcqlFormatId(), Map.of(
                        "sd-jwt_alg_values", List.of("ES256"),
                        "kb-jwt_alg_values", List.of("ES256"))));
        if (responseEncryptionKey != null) {
            // OpenID4VP §response_encryption: advertise the encryption key via client_metadata.jwks
            // and the content-encryption algorithms accepted. HAIP §5 requires both A128GCM and
            // A256GCM to be offered, not just one.
            Map<String, Object> jwks = Map.of("keys", List.of(responseEncryptionKey.toPublicJWK().toJSONObject()));
            clientMetadata.put("jwks", jwks);
            clientMetadata.put("encrypted_response_enc_values_supported", List.of("A128GCM", "A256GCM"));
        }
        return clientMetadata;
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
        // The x5c header carries the leaf and any intermediates the wallet needs to build a path
        // to a trust anchor it already holds separately — it must NOT include the trust anchor
        // (self-signed root) itself (OID4VP-1FINAL-5.9.3: "Trust anchor certificate must not be
        // included in x5c chain"). A cert is self-signed when its issuer equals its subject.
        List<Base64> chain = new ArrayList<>();
        chain.add(Base64.encode(signingMaterial.leaf().getEncoded()));
        for (X509Certificate intermediate : signingMaterial.chain()) {
            boolean selfSigned = intermediate.getSubjectX500Principal().equals(intermediate.getIssuerX500Principal());
            if (!selfSigned) {
                chain.add(Base64.encode(intermediate.getEncoded()));
            }
        }
        return chain;
    }

    private JWSAlgorithm signingAlgorithm() {
        if (signingMaterial.privateKey() instanceof ECPrivateKey ecKey) {
            return ecSigningAlgorithm(ecKey);
        }
        if (signingMaterial.privateKey() instanceof RSAPrivateKey) {
            return JWSAlgorithm.RS256;
        }
        throw new IllegalStateException(
                "Unsupported signing key type: " + signingMaterial.privateKey().getAlgorithm()
                        + " (only RSA and EC keys are supported)");
    }

    /**
     * RFC 7518 defines {@code ES256}/{@code ES384}/{@code ES512} specifically for NIST P-256/384/521
     * — there is no separate registered JOSE {@code alg} for Brainpool curves (RFC 5639), and Nimbus
     * (this project's JOSE library) has no built-in {@code Curve} constant for them either. This
     * method picks the {@code alg} by the key's field size rather than by exact curve identity: a
     * 256-bit curve's ECDSA signature is always a 32-byte-r/32-byte-s pair regardless of which
     * 256-bit curve produced it, so BrainpoolP256r1 and P-256 are wire-compatible under {@code ES256}
     * (same reasoning for BrainpoolP384r1 under {@code ES384}). ENISA's ECCG "Agreed Cryptographic
     * Mechanisms v2.0" (Apr 2025), the document EUDI ARF Annex 2.03 defers to for algorithm approval,
     * lists BrainpoolP256r1/P384r1/P512r1 as "Recommended" — the same tier as the NIST curves — so
     * this isn't a niche choice.
     *
     * <p><b>Not yet empirically verified against a real wallet or the OIDF conformance suite</b> —
     * a verifier that strictly cross-checks {@code alg} against the curve embedded in the x5c leaf
     * certificate (rather than deriving the curve from the certificate alone, which is what {@code
     * alg} can't fully specify here) could still reject this. See
     * {@code eudi-rp-mock-wallet/COMPATIBILITY.md}.
     *
     * <p>BrainpoolP512r1 is deliberately unsupported: it's a 512-bit curve, not 521-bit, so it does
     * NOT fit {@code ES512}'s fixed 66-byte-r/66-byte-s encoding (defined for P-521). Guessing an
     * alg here would repeat the exact class of bug this method fixes, so it fails loudly instead.
     */
    private static JWSAlgorithm ecSigningAlgorithm(ECPrivateKey ecKey) {
        int fieldSizeBits = ecKey.getParams().getCurve().getField().getFieldSize();
        return switch (fieldSizeBits) {
            case 256 -> JWSAlgorithm.ES256; // NIST P-256 or BrainpoolP256r1
            case 384 -> JWSAlgorithm.ES384; // NIST P-384 or BrainpoolP384r1
            case 521 -> JWSAlgorithm.ES512; // NIST P-521 only
            default -> throw new IllegalStateException(
                    "Unsupported EC curve: " + fieldSizeBits + "-bit field. No JOSE ES* algorithm is "
                            + "defined for this key size (256-, 384-, and 521-bit curves are supported; "
                            + "note BrainpoolP512r1 is 512-bit, not 521-bit, and is not covered by ES512).");
        };
    }

    private JWSSigner signer() throws JOSEException {
        if (signingMaterial.privateKey() instanceof ECPrivateKey ecKey) {
            // Nimbus's single-arg ECDSASigner(ECPrivateKey) auto-detects the curve itself and
            // rejects anything that isn't P-256/384/521 outright — it doesn't know Brainpool exists
            // (verified empirically: it throws "The EC key curve is not supported" for a real
            // BrainpoolP256r1 key). The (PrivateKey, Curve) overload instead takes the curve as an
            // explicit hint used only to determine the expected signature byte length for JOSE's
            // fixed-length r/s encoding — the actual EC math still comes from the real key via the
            // JCA provider, so passing Nimbus's P-256/384/521 constant for a same-bit-length
            // Brainpool key is correct, not a lie: BrainpoolP256r1's ECDSA signature is a 32-byte-r/
            // 32-byte-s pair, identically shaped to P-256's.
            //
            // Separately, the default JCA provider chain's ECDSA signature engine (JDK's own SunEC)
            // doesn't understand BouncyCastle's ECNamedCurveSpec for Brainpool keys even once Nimbus
            // accepts the curve hint above — verified empirically ("Curve not supported:
            // ECNamedCurveSpec"). Forcing the BC provider for the actual JCA Signature operation
            // fixes it; BC registers and understands Brainpool curves natively.
            ECDSASigner signer = new ECDSASigner(ecKey, curveHintFor(ecSigningAlgorithm(ecKey)));
            signer.getJCAContext().setProvider(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
            return signer;
        }
        if (signingMaterial.privateKey() instanceof RSAPrivateKey rsaKey) {
            return new RSASSASigner(rsaKey);
        }
        throw new IllegalStateException(
                "Unsupported signing key type: " + signingMaterial.privateKey().getAlgorithm());
    }

    private static Curve curveHintFor(JWSAlgorithm alg) {
        if (JWSAlgorithm.ES256.equals(alg)) {
            return Curve.P_256;
        }
        if (JWSAlgorithm.ES384.equals(alg)) {
            return Curve.P_384;
        }
        if (JWSAlgorithm.ES512.equals(alg)) {
            return Curve.P_521;
        }
        throw new IllegalStateException("Unexpected EC JWS algorithm: " + alg);
    }

    private static String generateNonce() {
        byte[] bytes = new byte[16]; // 128 bits, per OpenID4VP's nonce entropy requirement
        SECURE_RANDOM.nextBytes(bytes);
        // Base64URL, not Base64 — a plain Base64 nonce can contain '+', '/', '=', which are not
        // URL-safe and were flagged as an interop risk (OID4VP-1FINAL-5.2).
        return Base64URL.encode(bytes).toString();
    }
}
