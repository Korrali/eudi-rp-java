package com.korrali.eudirp.presentation;

import com.korrali.eudirp.cert.RpKeyMaterial;
import com.korrali.eudirp.cert.support.TestCertificates;
import com.korrali.eudirp.presentation.support.TestSdJwtVc;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PresentationFlowTest {

    private static DeclaredAttributeSet declaredAttributes(Path tempDir, String... paths) throws Exception {
        Path file = tempDir.resolve("declared-attributes.txt");
        Files.writeString(file, String.join("\n", paths));
        return new LocalRegistrationMetadataProvider(file).declaredAttributes();
    }

    private static RpKeyMaterial rpKeyMaterial() {
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test RP Access CA");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS));
        return new RpKeyMaterial(leaf.privateKey(), leaf.certificate(), List.of(ca.certificate()));
    }

    @Test
    void buildsASignedRequestObjectWithTheExpectedShape(@TempDir Path tempDir) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name", "family_name");
        RpKeyMaterial rpKey = rpKeyMaterial();

        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(declared.claim("given_name"), declared.claim("family_name")));

        SignedPresentationRequest signed = new PresentationRequestBuilder(rpKey, declared)
                .credential(query)
                .responseUri("https://rp.example.org/wallet/direct_post")
                .state("abc123")
                .build();

        assertThat(signed.clientId()).startsWith("x509_hash:");
        assertThat(signed.responseMode()).isEqualTo(ResponseMode.DIRECT_POST);

        SignedJWT parsed = SignedJWT.parse(signed.requestObjectJwt());
        assertThat(parsed.getHeader().getType().toString()).isEqualTo("oauth-authz-req+jwt");
        // leaf only — the CA is self-signed (the trust anchor) and must NOT appear in x5c
        // (OID4VP-1FINAL-5.9.3, confirmed against the real OIDF conformance suite)
        assertThat(parsed.getHeader().getX509CertChain()).hasSize(1);
        assertThat(parsed.getJWTClaimsSet().getStringClaim("response_type")).isEqualTo("vp_token");
        assertThat(parsed.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo(signed.clientId());
        assertThat(parsed.getJWTClaimsSet().getStringClaim("nonce")).isNotBlank();

        // nonce must be URL-safe base64 — no '+', '/', or '=' (OID4VP-1FINAL-5.2)
        String nonce = parsed.getJWTClaimsSet().getStringClaim("nonce");
        assertThat(nonce).doesNotContain("+", "/", "=");

        // aud is required on the Request Object; this library never does dynamic wallet-metadata
        // discovery, so it's always the static-discovery fixed value (OpenID4VP "aud of a Request
        // Object"). Nimbus normalizes the registered "aud" claim to a JSON array on the wire even
        // when set as a single string (RFC 7519 §4.1.3's general case, not the single-string
        // special case) — verified against the actual serialized+reparsed JWT, not assumed.
        assertThat(parsed.getJWTClaimsSet().getAudience()).containsExactly("https://self-issued.me/v2");

        // vp_formats_supported is REQUIRED in client_metadata regardless of response_mode
        // (OID4VP-1FINALA-B.2.2 / B.3.4)
        @SuppressWarnings("unchecked")
        Map<String, Object> clientMetadataAlwaysPresent = (Map<String, Object>) parsed.getJWTClaimsSet().getClaim("client_metadata");
        assertThat(clientMetadataAlwaysPresent).containsKey("vp_formats_supported");

        @SuppressWarnings("unchecked")
        Map<String, Object> dcqlQuery = (Map<String, Object>) parsed.getJWTClaimsSet().getClaim("dcql_query");
        assertThat(dcqlQuery).containsKey("credentials");
    }

    @Test
    void refusesToBuildARequestForAnUndeclaredAttribute(@TempDir Path tempDir) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name");
        RpKeyMaterial rpKey = rpKeyMaterial();

        // Bypasses DeclaredAttributeSet.claim(...) on purpose, to exercise the builder's own
        // defense-in-depth check.
        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(DcqlClaimQuery.of("national_id_number")));

        PresentationRequestBuilder builder = new PresentationRequestBuilder(rpKey, declared)
                .credential(query)
                .responseUri("https://rp.example.org/wallet/direct_post")
                .state("abc123");

        assertThatThrownBy(builder::build).isInstanceOf(DeclaredScopeViolationException.class);
    }

    @Test
    void declaredAttributeSetRejectsUndeclaredClaimsAtSourceToo(@TempDir Path tempDir) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name");

        assertThatThrownBy(() -> declared.claim("family_name"))
                .isInstanceOf(UndeclaredAttributeException.class);
    }

    @Test
    void verifiesAWalletResponseAndResolvesDisclosedClaims(@TempDir Path tempDir) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name", "family_name");
        RpKeyMaterial rpKey = rpKeyMaterial();

        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(declared.claim("given_name"), declared.claim("family_name")));

        SignedPresentationRequest signed = new PresentationRequestBuilder(rpKey, declared)
                .credential(query)
                .responseUri("https://rp.example.org/wallet/direct_post")
                .state("abc123")
                .build();

        TestCertificates.IssuedCertificate issuerCa = TestCertificates.selfSignedCa("Test Credential Issuer");
        RSAPrivateKey issuerPrivateKey = (RSAPrivateKey) issuerCa.privateKey();
        RSAPublicKey issuerPublicKey = (RSAPublicKey) issuerCa.certificate().getPublicKey();

        String presentation = TestSdJwtVc.build(issuerPrivateKey, "https://issuer.example.org",
                "https://credentials.example.com/identity_credential",
                List.of(new TestSdJwtVc.ClaimToDisclose("given_name", "Ada"),
                        new TestSdJwtVc.ClaimToDisclose("family_name", "Lovelace")));

        AuthorizationResponse response = AuthorizationResponse.fromDirectPostForm(
                "{\"my_credential\":[\"" + presentation + "\"]}", "abc123");

        PresentationResponseVerifier verifier = new PresentationResponseVerifier(
                jwt -> new RSASSAVerifier(issuerPublicKey));

        List<VerifiedPresentation> results = verifier.verify(response, signed, List.of(query));

        assertThat(results).hasSize(1);
        assertThat(results.get(0).disclosedClaims()).containsEntry("given_name", "Ada");
        assertThat(results.get(0).disclosedClaims()).containsEntry("family_name", "Lovelace");
        assertThat(results.get(0).format()).isEqualTo(CredentialFormat.SD_JWT_VC);
    }

    @Test
    void rejectsAResponseWithAMismatchedState(@TempDir Path tempDir) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name");
        RpKeyMaterial rpKey = rpKeyMaterial();
        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(declared.claim("given_name")));

        SignedPresentationRequest signed = new PresentationRequestBuilder(rpKey, declared)
                .credential(query).responseUri("https://rp.example.org/wallet/direct_post").state("abc123").build();

        AuthorizationResponse response = new AuthorizationResponse(Map.of(), "wrong-state");
        PresentationResponseVerifier verifier = new PresentationResponseVerifier(jwt -> null);

        assertThatThrownBy(() -> verifier.verify(response, signed, List.of(query)))
                .isInstanceOf(PresentationVerificationException.class);
    }

    @Test
    void directPostJwtRoundTripsThroughRealEncryptionAndDecryption(@TempDir Path tempDir) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name");
        RpKeyMaterial rpKey = rpKeyMaterial();
        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(declared.claim("given_name")));

        SignedPresentationRequest signed = new PresentationRequestBuilder(rpKey, declared)
                .credential(query)
                .responseMode(ResponseMode.DIRECT_POST_JWT)
                .responseUri("https://rp.example.org/wallet/direct_post")
                .state("encrypted-state-456")
                .build();

        assertThat(signed.responseEncryptionKey()).isNotNull();

        // The request object itself must advertise the encryption key per OpenID4VP
        // §response_encryption (client_metadata.jwks) — confirm it's actually there, not just
        // held server-side.
        SignedJWT parsedRequest = SignedJWT.parse(signed.requestObjectJwt());
        @SuppressWarnings("unchecked")
        Map<String, Object> clientMetadata = (Map<String, Object>) parsedRequest.getJWTClaimsSet().getClaim("client_metadata");
        assertThat(clientMetadata).containsKey("jwks");
        // HAIP §5 requires both, not just one (HAIP-5-5)
        assertThat(clientMetadata.get("encrypted_response_enc_values_supported"))
                .isEqualTo(List.of("A128GCM", "A256GCM"));

        // Simulate the wallet: it only ever sees the PUBLIC half of the key (from client_metadata),
        // never the private key our RP holds server-side.
        TestCertificates.IssuedCertificate issuerCa = TestCertificates.selfSignedCa("Test Credential Issuer");
        String presentation = TestSdJwtVc.build((RSAPrivateKey) issuerCa.privateKey(), "https://issuer.example.org",
                "https://credentials.example.com/identity_credential",
                List.of(new TestSdJwtVc.ClaimToDisclose("given_name", "Ada")));

        ECKey walletSideEncryptionKey = signed.responseEncryptionKey().toPublicJWK();
        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                .keyID(walletSideEncryptionKey.getKeyID())
                .build();
        String payloadJson = "{\"vp_token\":{\"my_credential\":[\"" + presentation + "\"]},\"state\":\"" + signed.state() + "\"}";
        JWEObject jwe = new JWEObject(jweHeader, new Payload(payloadJson));
        jwe.encrypt(new ECDHEncrypter(walletSideEncryptionKey));
        String compactJwe = jwe.serialize();

        // RP side: decrypt using the private key it kept from the original build() call.
        AuthorizationResponse response = AuthorizationResponse.fromDirectPostJwt(compactJwe, signed.responseEncryptionKey());
        assertThat(response.state()).isEqualTo("encrypted-state-456");

        PresentationResponseVerifier verifier = new PresentationResponseVerifier(
                jwt -> new RSASSAVerifier((java.security.interfaces.RSAPublicKey) issuerCa.certificate().getPublicKey()));
        List<VerifiedPresentation> results = verifier.verify(response, signed, List.of(query));

        assertThat(results).hasSize(1);
        assertThat(results.get(0).disclosedClaims()).containsEntry("given_name", "Ada");
    }

    /**
     * Before this fix, {@code signingAlgorithm()} declared {@code ES256} for ANY EC key regardless
     * of curve — so a P-384 or P-521 RP key (both plain NIST curves, nothing exotic) would have been
     * signed correctly but mislabeled, which a strict wallet should reject. This wasn't a
     * Brainpool-only bug; it affected every non-P-256 EC key this library never had a fixture for.
     */
    @Test
    void signsWithP384AndDeclaresES384NotES256(@TempDir Path tempDir) throws Exception {
        assertCorrectAlgForCurve(tempDir, "secp384r1", com.nimbusds.jose.JWSAlgorithm.ES384);
    }

    @Test
    void signsWithP521AndDeclaresES512(@TempDir Path tempDir) throws Exception {
        assertCorrectAlgForCurve(tempDir, "secp521r1", com.nimbusds.jose.JWSAlgorithm.ES512);
    }

    /**
     * ENISA's ECCG "Agreed Cryptographic Mechanisms v2.0" (Apr 2025) — the document EUDI ARF
     * Annex 2.03 defers to for algorithm approval — lists BrainpoolP256r1 as "Recommended", the
     * same tier as NIST P-256. Germany's BSI recommends it specifically for sovereign deployments.
     */
    @Test
    void signsWithBrainpoolP256r1AndDeclaresES256(@TempDir Path tempDir) throws Exception {
        assertCorrectAlgForCurve(tempDir, "brainpoolP256r1", com.nimbusds.jose.JWSAlgorithm.ES256);
    }

    @Test
    void signsWithBrainpoolP384r1AndDeclaresES384(@TempDir Path tempDir) throws Exception {
        assertCorrectAlgForCurve(tempDir, "brainpoolP384r1", com.nimbusds.jose.JWSAlgorithm.ES384);
    }

    /**
     * BrainpoolP512r1 is deliberately rejected, not silently mapped to ES512 (which is defined for
     * the 521-bit P-521 curve, not this 512-bit one) — see the javadoc on
     * {@code PresentationRequestBuilder.ecSigningAlgorithm}.
     */
    @Test
    void refusesToSignWithBrainpoolP512r1(@TempDir Path tempDir) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name");
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test RP Access CA", "brainpoolP512r1");
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, "brainpoolP512r1", "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS), null, null);
        RpKeyMaterial rpKey = new RpKeyMaterial(leaf.privateKey(), leaf.certificate(), List.of(ca.certificate()));

        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(declared.claim("given_name")));

        PresentationRequestBuilder builder = new PresentationRequestBuilder(rpKey, declared)
                .credential(query).responseUri("https://rp.example.org/wallet/direct_post").state("abc123");

        assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("512-bit");
    }

    private static void assertCorrectAlgForCurve(Path tempDir, String curveName, com.nimbusds.jose.JWSAlgorithm expectedAlg) throws Exception {
        DeclaredAttributeSet declared = declaredAttributes(tempDir, "given_name");
        TestCertificates.IssuedCertificate ca = TestCertificates.selfSignedCa("Test RP Access CA", curveName);
        Instant now = Instant.now();
        TestCertificates.IssuedCertificate leaf = TestCertificates.leaf(
                ca, curveName, "rp.example.org", now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS), null, null);
        RpKeyMaterial rpKey = new RpKeyMaterial(leaf.privateKey(), leaf.certificate(), List.of(ca.certificate()));

        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(declared.claim("given_name")));

        SignedPresentationRequest signed = new PresentationRequestBuilder(rpKey, declared)
                .credential(query)
                .responseUri("https://rp.example.org/wallet/direct_post")
                .state("abc123")
                .build();

        SignedJWT parsed = SignedJWT.parse(signed.requestObjectJwt());
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(expectedAlg);

        // Not just the declared header — the signature must actually verify against the leaf's
        // real public key, proving the mechanical sign/verify round trip genuinely works for this
        // curve, not just that the label looks right. Nimbus's ECDSAVerifier has no explicit-curve
        // overload (unlike ECDSASigner) and its auto-detection rejects Brainpool the same way, so
        // this verifies directly via the same ECDSA.getSignerAndVerifier(alg, provider) utility
        // Nimbus itself uses internally, forcing the BC provider explicitly.
        byte[] derSignature = com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(parsed.getSignature().decode());
        java.security.Signature verifier = com.nimbusds.jose.crypto.impl.ECDSA.getSignerAndVerifier(
                expectedAlg, java.security.Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME));
        verifier.initVerify((java.security.interfaces.ECPublicKey) leaf.certificate().getPublicKey());
        verifier.update(parsed.getSigningInput());
        assertThat(verifier.verify(derSignature)).isTrue();
    }
}
