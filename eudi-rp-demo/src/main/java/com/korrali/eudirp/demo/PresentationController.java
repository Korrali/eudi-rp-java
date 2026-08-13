package com.korrali.eudirp.demo;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.korrali.eudirp.cert.HotReloadingCertificateResolver;
import com.korrali.eudirp.cert.RevocationChecker;
import com.korrali.eudirp.cert.RpKeyMaterial;
import com.korrali.eudirp.mockwallet.MockWallet;
import com.korrali.eudirp.mockwallet.MockWalletResponse;
import com.korrali.eudirp.presentation.AuthorizationResponse;
import com.korrali.eudirp.presentation.DcqlClaimQuery;
import com.korrali.eudirp.presentation.DcqlCredentialQuery;
import com.korrali.eudirp.presentation.CredentialFormat;
import com.korrali.eudirp.presentation.DeclaredAttributeSet;
import com.korrali.eudirp.presentation.PresentationRequestBuilder;
import com.korrali.eudirp.presentation.PresentationResponseVerifier;
import com.korrali.eudirp.presentation.RegistrationMetadataProvider;
import com.korrali.eudirp.presentation.ResponseMode;
import com.korrali.eudirp.presentation.SignedPresentationRequest;
import com.korrali.eudirp.presentation.VerifiedPresentation;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class PresentationController {

    private final HotReloadingCertificateResolver certificateResolver;
    private final RegistrationMetadataProvider registrationMetadataProvider;
    private final RevocationChecker revocationChecker;
    private final MockWallet mockWallet;
    private final TransactionStore store;
    private final String baseUrl;
    private final String walletMode;

    public PresentationController(HotReloadingCertificateResolver certificateResolver,
                                   RegistrationMetadataProvider registrationMetadataProvider,
                                   RevocationChecker revocationChecker,
                                   MockWallet mockWallet,
                                   TransactionStore store,
                                   @Value("${eudirp.demo.base-url}") String baseUrl,
                                   @Value("${eudirp.demo.wallet-mode}") String walletMode) {
        this.certificateResolver = certificateResolver;
        this.registrationMetadataProvider = registrationMetadataProvider;
        this.revocationChecker = revocationChecker;
        this.mockWallet = mockWallet;
        this.store = store;
        this.baseUrl = baseUrl;
        this.walletMode = walletMode;
    }

    @PostMapping("/presentations")
    public Map<String, Object> createPresentation(
            @RequestParam(value = "responseMode", defaultValue = "direct_post") String responseModeParam) throws Exception {
        String id = UUID.randomUUID().toString();

        RpKeyMaterial rpKey = certificateResolver.resolveValid();
        DeclaredAttributeSet declared = registrationMetadataProvider.declaredAttributes();

        DcqlCredentialQuery query = new DcqlCredentialQuery(
                "identity_credential", CredentialFormat.SD_JWT_VC,
                List.of("https://credentials.example.com/identity_credential"),
                List.of(declared.claim("given_name"), declared.claim("family_name"), declared.claim("birth_date")));

        // "direct_post_jwt" opts into encrypted responses (OpenID4VP §response_encryption) — used
        // for interop testing (e.g. the OIDF OpenID4VP conformance suite) where the HAIP profile's
        // credential-format/response-mode combination requires it. The default mock-wallet flow
        // stays on plain direct_post.
        ResponseMode responseMode = "direct_post_jwt".equals(responseModeParam)
                ? ResponseMode.DIRECT_POST_JWT : ResponseMode.DIRECT_POST;

        String responseUri = baseUrl + "/api/wallet/direct_post/" + id;
        SignedPresentationRequest signedRequest = new PresentationRequestBuilder(rpKey, declared)
                .credential(query)
                .responseMode(responseMode)
                .responseUri(responseUri)
                .state(UUID.randomUUID().toString())
                .build();

        String revocationOutcome;
        boolean revocationAttempted;
        try {
            var status = revocationChecker.check(rpKey.leaf(), rpKey.chain());
            revocationAttempted = true;
            revocationOutcome = status.revoked() ? "revoked" : "good (source=" + status.source() + ")";
        } catch (Exception e) {
            revocationAttempted = true;
            revocationOutcome = "check could not be completed: " + e.getMessage();
        }

        Transaction transaction = new Transaction(id, signedRequest, List.of(query),
                rpKey.chain().isEmpty() ? "self-signed" : rpKey.chain().get(0).getSubjectX500Principal().getName(),
                revocationAttempted, revocationOutcome);
        store.put(transaction);

        String requestUri = baseUrl + "/api/wallet/request.jwt/" + id;
        String deepLink = "openid4vp://?client_id=" + urlEncode(signedRequest.clientId())
                + "&request_uri=" + urlEncode(requestUri);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("transactionId", id);
        response.put("deepLink", deepLink);
        response.put("clientId", signedRequest.clientId());
        response.put("walletMode", walletMode);
        return response;
    }

    @GetMapping(value = "/presentations/{id}/qr.png", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> qrCode(@PathVariable String id) throws Exception {
        Transaction tx = store.find(id).orElseThrow();
        String requestUri = baseUrl + "/api/wallet/request.jwt/" + id;
        String deepLink = "openid4vp://?client_id=" + urlEncode(tx.signedRequest.clientId())
                + "&request_uri=" + urlEncode(requestUri);

        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(deepLink, BarcodeFormat.QR_CODE, 320, 320);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", out);
        return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(out.toByteArray());
    }

    @GetMapping(value = "/wallet/request.jwt/{id}", produces = "application/oauth-authz-req+jwt")
    public ResponseEntity<String> requestObject(@PathVariable String id) {
        Transaction tx = store.find(id).orElseThrow();
        tx.state.compareAndSet(Transaction.State.AWAITING_SCAN, Transaction.State.REQUEST_SENT);
        return ResponseEntity.ok(tx.signedRequest.requestObjectJwt());
    }

    @PostMapping(value = "/wallet/direct_post/{id}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> directPost(@PathVariable String id,
                                            @RequestParam(value = "vp_token", required = false) String vpToken,
                                            @RequestParam(value = "response", required = false) String encryptedResponse,
                                            @RequestParam(value = "state", required = false) String state) {
        Transaction tx = store.find(id).orElseThrow();
        if (encryptedResponse != null) {
            completeWithEncryptedWalletResponse(tx, encryptedResponse);
        } else {
            completeWithWalletResponse(tx, vpToken, state);
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping("/presentations/{id}/simulate-scan")
    public Map<String, Object> simulateScan(@PathVariable String id) throws Exception {
        Transaction tx = store.find(id).orElseThrow();
        tx.state.set(Transaction.State.REQUEST_SENT);
        Thread.sleep(400); // purely so the UI can show the intermediate state; not needed in production

        MockWalletResponse walletResponse = mockWallet.respondTo(tx.signedRequest.requestObjectJwt());
        completeWithWalletResponse(tx, walletResponse.vpTokenJson(), walletResponse.state());
        return Map.of("state", tx.state.get().name());
    }

    private void completeWithEncryptedWalletResponse(Transaction tx, String encryptedResponse) {
        tx.state.set(Transaction.State.RESPONSE_RECEIVED);
        tx.rawResponseJson = "(encrypted; see decrypted vp_token below)";
        try {
            AuthorizationResponse response = AuthorizationResponse.fromDirectPostJwt(
                    encryptedResponse, tx.signedRequest.responseEncryptionKey());

            List<VerifiedPresentation> results = new ArrayList<>();
            for (var entry : response.vpToken().entrySet()) {
                for (String presentation : entry.getValue()) {
                    var sdJwtVc = com.korrali.eudirp.presentation.SdJwtVc.parse(presentation);
                    Map<String, Object> disclosedClaims = sdJwtVc.resolveDisclosedClaims();
                    results.add(new VerifiedPresentation(entry.getKey(), CredentialFormat.SD_JWT_VC, disclosedClaims));
                }
            }
            tx.result = results;
            tx.issuerSignatureNote = "Transport decrypted successfully (response_mode=direct_post.jwt). "
                    + "Issuer signature NOT verified — this build has no configured trust for external "
                    + "test issuers (credential-issuer trust is a documented out-of-scope boundary, "
                    + "separate from the RP's own certificate lifecycle, which is this project's actual focus).";
            tx.state.set(Transaction.State.VERIFIED);
        } catch (Exception e) {
            tx.errorType = e.getClass().getSimpleName();
            tx.errorMessage = e.getMessage();
            tx.state.set(Transaction.State.FAILED);
        }
    }

    private void completeWithWalletResponse(Transaction tx, String vpTokenJson, String state) {
        tx.state.set(Transaction.State.RESPONSE_RECEIVED);
        tx.rawResponseJson = vpTokenJson;
        try {
            AuthorizationResponse response = AuthorizationResponse.fromDirectPostForm(vpTokenJson, state);
            RSAPublicKey mockIssuerKey = mockWallet.issuerPublicKey();
            PresentationResponseVerifier verifier = new PresentationResponseVerifier(jwt -> new RSASSAVerifier(mockIssuerKey));
            List<VerifiedPresentation> results = verifier.verify(response, tx.signedRequest, tx.queries);
            tx.result = results;
            tx.state.set(Transaction.State.VERIFIED);
        } catch (Exception e) {
            tx.errorType = e.getClass().getSimpleName();
            tx.errorMessage = e.getMessage();
            tx.state.set(Transaction.State.FAILED);
        }
    }

    @GetMapping("/presentations/{id}")
    public Map<String, Object> status(@PathVariable String id) {
        Transaction tx = store.find(id).orElseThrow();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("state", tx.state.get().name());
        response.put("rpCertificateIssuer", tx.rpCertificateIssuer);
        response.put("revocationCheckAttempted", tx.revocationCheckAttempted);
        response.put("revocationCheckOutcome", tx.revocationCheckOutcome);
        if (tx.result != null) {
            List<Map<String, Object>> credentials = tx.result.stream().map(vp -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("credentialId", vp.credentialId());
                m.put("format", vp.format().name());
                m.put("disclosedClaims", vp.disclosedClaims());
                return m;
            }).toList();
            response.put("credentials", credentials);
        }
        if (tx.issuerSignatureNote != null) {
            response.put("issuerSignatureNote", tx.issuerSignatureNote);
        }
        if (tx.errorType != null) {
            response.put("errorType", tx.errorType);
            response.put("errorMessage", tx.errorMessage);
        }
        return response;
    }

    @GetMapping("/presentations/{id}/raw")
    public Map<String, Object> raw(@PathVariable String id) {
        Transaction tx = store.find(id).orElseThrow();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("requestObjectJwt", tx.signedRequest.requestObjectJwt());
        response.put("clientId", tx.signedRequest.clientId());
        response.put("nonce", tx.signedRequest.nonce());
        response.put("responseUri", tx.signedRequest.responseUri());
        response.put("responseMode", tx.signedRequest.responseMode().wireValue());
        response.put("vpTokenJson", tx.rawResponseJson);
        return response;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
