package com.korrali.eudirp.mockwallet;

import com.korrali.eudirp.cert.RpKeyMaterial;
import com.korrali.eudirp.presentation.AuthorizationResponse;
import com.korrali.eudirp.presentation.CredentialFormat;
import com.korrali.eudirp.presentation.DcqlClaimQuery;
import com.korrali.eudirp.presentation.DcqlCredentialQuery;
import com.korrali.eudirp.presentation.DeclaredAttributeSet;
import com.korrali.eudirp.presentation.PresentationRequestBuilder;
import com.korrali.eudirp.presentation.PresentationResponseVerifier;
import com.korrali.eudirp.presentation.SignedPresentationRequest;
import com.korrali.eudirp.presentation.VerifiedPresentation;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Builds a real signed request with {@code eudi-rp-core}, hands it to {@link MockWallet}, and
 * verifies the response with {@code eudi-rp-core}'s own verifier — the same round trip a real
 * deployment would run, minus an actual wallet app and QR scan.
 */
class MockWalletEndToEndTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void mockWalletProducesAResponseThatVerifiesCleanly() throws Exception {
        RpKeyMaterial rpKey = generateRpKeyMaterial();
        DeclaredAttributeSet declared = new DeclaredAttributeSet(Set.of("given_name", "family_name"));

        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "my_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(DcqlClaimQuery.of("given_name"), DcqlClaimQuery.of("family_name")));

        SignedPresentationRequest signedRequest = new PresentationRequestBuilder(rpKey, declared)
                .credential(query)
                .responseUri("https://rp.example.org/wallet/direct_post")
                .state("test-state-123")
                .build();

        MockWallet wallet = new MockWallet();
        MockWalletResponse walletResponse = wallet.respondTo(signedRequest.requestObjectJwt());

        assertThat(walletResponse.state()).isEqualTo("test-state-123");
        assertThat(walletResponse.responseUri()).isEqualTo("https://rp.example.org/wallet/direct_post");

        AuthorizationResponse response = AuthorizationResponse.fromDirectPostForm(
                walletResponse.vpTokenJson(), walletResponse.state());

        // A real deployment resolves the issuer's key from configured issuer trust material, per
        // IssuerSignatureVerifierResolver's documented boundary. MockWallet exposes its own mock
        // issuer key for exactly this purpose — see its javadoc.
        RSAPublicKey mockIssuerPublicKey = wallet.issuerPublicKey();
        PresentationResponseVerifier verifier = new PresentationResponseVerifier(jwt -> new RSASSAVerifier(mockIssuerPublicKey));

        List<VerifiedPresentation> results = verifier.verify(response, signedRequest, List.of(query));

        assertThat(results).hasSize(1);
        assertThat(results.get(0).disclosedClaims()).containsEntry("given_name", "Ada");
        assertThat(results.get(0).disclosedClaims()).containsEntry("family_name", "Lovelace");
    }

    @Test
    void mockWalletRejectsARequestObjectWithTheWrongTypHeader() {
        MockWallet wallet = new MockWallet();

        assertThatThrownBy(() -> wallet.respondTo("not.a.jwt"))
                .isInstanceOf(MockWalletException.class);
    }

    private static RpKeyMaterial generateRpKeyMaterial() throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        X500Name caName = new X500Name("CN=Mock Wallet Test CA");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(1), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)), caName, caKeyPair.getPublic());
        caBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate caCert = sign(caBuilder, caKeyPair.getPrivate());

        KeyPair leafKeyPair = generateKeyPair();
        X500Name leafName = new X500Name("CN=rp.example.org");
        JcaX509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(2), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)), leafName, leafKeyPair.getPublic());
        leafBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
        X509Certificate leafCert = sign(leafBuilder, caKeyPair.getPrivate());

        return new RpKeyMaterial(leafKeyPair.getPrivate(), leafCert, List.of(caCert));
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, java.security.PrivateKey signerKey) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
