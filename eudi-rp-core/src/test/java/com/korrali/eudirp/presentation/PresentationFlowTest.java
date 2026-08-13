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
        assertThat(parsed.getHeader().getX509CertChain()).hasSize(2); // leaf + CA
        assertThat(parsed.getJWTClaimsSet().getStringClaim("response_type")).isEqualTo("vp_token");
        assertThat(parsed.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo(signed.clientId());
        assertThat(parsed.getJWTClaimsSet().getStringClaim("nonce")).isNotBlank();

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
        assertThat(clientMetadata).containsKey("encrypted_response_enc_values_supported");

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
}
