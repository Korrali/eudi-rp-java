package com.korrali.eudirp.cert.support;

import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Date;

/**
 * A minimal, in-process OCSP responder for tests: signs every response with the issuing CA's own
 * key (no separately-delegated OCSP-signer certificate), returning a single fixed status for
 * whatever certificate is asked about — enough to exercise {@code OcspRevocationChecker} against a
 * real signed HTTP response instead of mocking it.
 */
public final class TestOcspResponder implements AutoCloseable {

    private final HttpServer server;
    private final URI uri;

    private TestOcspResponder(HttpServer server, URI uri) {
        this.server = server;
        this.uri = uri;
    }

    public URI uri() {
        return uri;
    }

    public static TestOcspResponder startAlwaysReturning(TestCertificates.IssuedCertificate ca, CertificateStatus status)
            throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try {
                byte[] requestBytes = exchange.getRequestBody().readAllBytes();
                OCSPReq request = new OCSPReq(requestBytes);

                BasicOCSPRespBuilder respBuilder = new BasicOCSPRespBuilder(
                        new RespID(new JcaX509CertificateHolder(ca.certificate()).getSubject()));
                for (Req req : request.getRequestList()) {
                    respBuilder.addResponse(req.getCertID(), status);
                }

                ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ca.privateKey());
                BasicOCSPResp basicResp = respBuilder.build(signer, null, new Date());
                OCSPResp response = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);

                byte[] responseBytes = response.getEncoded();
                exchange.getResponseHeaders().add("Content-Type", "application/ocsp-response");
                exchange.sendResponseHeaders(200, responseBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            }
        });
        server.start();
        int port = server.getAddress().getPort();
        return new TestOcspResponder(server, URI.create("http://127.0.0.1:" + port + "/"));
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
