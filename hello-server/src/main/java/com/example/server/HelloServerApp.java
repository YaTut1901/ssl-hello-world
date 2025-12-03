package com.example.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class HelloServerApp {
    private static final String CA_ISSUE_ENDPOINT = System.getenv("CA_ISSUE_ENDPOINT");
    private static final Integer CA_SERVER_PORT = Integer.parseInt(System.getenv("CA_SERVER_PORT"));
    private static final String CA_ROOT_CERT_PATH = "/certs/ca-root.cer";
    private static final String SERVER_KEYSTORE_PATH = "server-keystore.jks";
    private static final String SERVER_KEYSTORE_PASSWORD = System.getenv("SERVER_PASSWORD");
    private static final String SERVER_CN = "hello-server";
    private static final Integer SERVER_PORT = Integer.parseInt(System.getenv("SERVER_PORT"));

    public static void main(String[] args) throws Exception {
        if (CA_ISSUE_ENDPOINT == null) {
            throw new Exception("CA_ISSUE_ENDPOINT is not set!");
        }

        if (CA_SERVER_PORT == null) {
            throw new Exception("CA_SERVER_PORT is not set!");
        }

        Security.addProvider(new BouncyCastleProvider());

        ServerCertManager certManager = new ServerCertManager(
                Path.of(SERVER_KEYSTORE_PATH),
                SERVER_KEYSTORE_PASSWORD.toCharArray(),
                Path.of(CA_ROOT_CERT_PATH),
                String.format("http://ca-server:%s%s", CA_SERVER_PORT, CA_ISSUE_ENDPOINT),
                SERVER_CN);

        SSLContext sslContext = certManager.ensureKeystoreAndBuildSslContext();

        HttpsServer server = HttpsServer.create(new InetSocketAddress(SERVER_PORT), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLContext ctx = getSSLContext();
                SSLParameters sslParams = ctx.getDefaultSSLParameters();
                sslParams.setNeedClientAuth(true);
                params.setSSLParameters(sslParams);
                System.out.println("[hello-server] HttpsConfigurator applied: needClientAuth=true");
            }
        });

        server.createContext("/name", new NameHandler());
        server.setExecutor(null);

        System.out.println("[hello-server] Started on port " + SERVER_PORT);
        server.start();
    }

    static class NameHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            if (exchange instanceof com.sun.net.httpserver.HttpsExchange) {
                com.sun.net.httpserver.HttpsExchange httpsExchange = (com.sun.net.httpserver.HttpsExchange) exchange;
                SSLSession session = httpsExchange.getSSLSession();
                System.out.println("[hello-server] Incoming HTTPS request");
                System.out.println("[hello-server]   CipherSuite: " + session.getCipherSuite());
                System.out.println("[hello-server]   Protocol   : " + session.getProtocol());
                try {
                    Certificate[] peer = session.getPeerCertificates();
                    if (peer != null && peer.length > 0) {
                        for (int i = 0; i < peer.length; i++) {
                            if (peer[i] instanceof X509Certificate) {
                                X509Certificate xc = (X509Certificate) peer[i];
                                System.out.println("[hello-server]     [client chain " + i + "] Subject=" + xc.getSubjectX500Principal()
                                        + ", Issuer=" + xc.getIssuerX500Principal()
                                        + ", Serial=" + xc.getSerialNumber());
                            }
                        }
                    }
                    System.out.println("[hello-server]   Peer principal: " + session.getPeerPrincipal());
                } catch (SSLPeerUnverifiedException e) {
                    System.out.println("[hello-server]   Client peer not verified (no certificate?): " + e.getMessage());
                }
                if (session.getLocalCertificates() != null) {
                    Certificate[] local = session.getLocalCertificates();
                    for (int i = 0; i < local.length; i++) {
                        if (local[i] instanceof X509Certificate) {
                            X509Certificate xc = (X509Certificate) local[i];
                            System.out.println("[hello-server]     [server chain " + i + "] Subject=" + xc.getSubjectX500Principal()
                                    + ", Issuer=" + xc.getIssuerX500Principal()
                                    + ", Serial=" + xc.getSerialNumber());
                        }
                    }
                }
            } else {
                System.out.println("[hello-server] Non-HTTPS exchange received");
            }

            byte[] body = SERVER_CN.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        }
    }
}
