package com.example.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Arrays;

public class HelloClientApp {
    private static final String CA_ISSUE_ENDPOINT = System.getenv("CA_ISSUE_ENDPOINT");
    private static final Integer CA_SERVER_PORT = Integer.parseInt(System.getenv("CA_SERVER_PORT"));
    private static final String CA_ROOT_CERT_PATH = "/certs/ca-root.cer";
    private static final String CLIENT_KEYSTORE_PATH = "client-keystore.jks";
    private static final String CLIENT_KEYSTORE_PASSWORD = System.getenv("CLIENT_PASSWORD");
    private static final String CLIENT_CN = "hello-client";
    private static final Integer CLIENT_PORT = Integer.parseInt(System.getenv("CLIENT_PORT"));
    private static final Integer SERVER_PORT = Integer.parseInt(System.getenv("SERVER_PORT"));

    public static void main(String[] args) throws Exception {
        if (CA_ISSUE_ENDPOINT == null) {
            throw new Exception("CA_ISSUE_ENDPOINT is not set!");
        }
        if (CA_SERVER_PORT == null) {
            throw new Exception("CA_SERVER_PORT is not set!");
        }
        if (CLIENT_KEYSTORE_PASSWORD == null || CLIENT_KEYSTORE_PASSWORD.isEmpty()) {
            throw new Exception("CLIENT_PASSWORD is not set!");
        }
        if (CLIENT_PORT == null) {
            throw new Exception("CLIENT_PORT is not set!");
        }
        if (SERVER_PORT == null) {
            throw new Exception("SERVER_PORT is not set!");
        }

        Security.addProvider(new BouncyCastleProvider());

        ClientCertManager certManager = new ClientCertManager(
                Path.of(CLIENT_KEYSTORE_PATH),
                CLIENT_KEYSTORE_PASSWORD.toCharArray(),
                Path.of(CA_ROOT_CERT_PATH),
                String.format("http://ca-server:%s%s", CA_SERVER_PORT, CA_ISSUE_ENDPOINT),
                CLIENT_CN
        );

        SSLContext sslContext = certManager.ensureKeystoreAndBuildSslContext();

        HttpServer server = HttpServer.create(new InetSocketAddress(CLIENT_PORT), 0);
        server.createContext("/hello-world", new HelloWorldHandler(sslContext));
        server.setExecutor(null);
        System.out.println("[hello-client] Started on port " + CLIENT_PORT);
        server.start();
    }

    static class HelloWorldHandler implements HttpHandler {
        private final SSLContext sslContext;

        HelloWorldHandler(SSLContext sslContext) {
            this.sslContext = sslContext;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                try {
                    debugFetchAndValidateServerChain(sslContext);
                } catch (Exception diagEx) {
                    System.out.println("[hello-client] DIAG: chain fetch/validate error: " + diagEx.getMessage());
                }

                URL url = URI.create(String.format("https://hello-server:%s/name", SERVER_PORT)).toURL();
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.setSSLSocketFactory(sslContext.getSocketFactory());
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                int code = conn.getResponseCode();
                System.out.println("[hello-client] HTTPS call to " + url);
                System.out.println("[hello-client]   CipherSuite: " + conn.getCipherSuite());
                try {
                    System.out.println("[hello-client]   Server peer principal: " + conn.getPeerPrincipal());
                    Certificate[] serverChain = conn.getServerCertificates();
                    if (serverChain != null) {
                        for (int i = 0; i < serverChain.length; i++) {
                            if (serverChain[i] instanceof X509Certificate) {
                                X509Certificate xc = (X509Certificate) serverChain[i];
                                System.out.println("[hello-client]     [server chain " + i + "] Subject=" + xc.getSubjectX500Principal()
                                        + ", Issuer=" + xc.getIssuerX500Principal()
                                        + ", Serial=" + xc.getSerialNumber());
                            }
                        }
                    }
                } catch (SSLPeerUnverifiedException e) {
                    System.out.println("[hello-client]   Server peer not verified: " + e.getMessage());
                }
                if (conn.getLocalPrincipal() != null) {
                    System.out.println("[hello-client]   Local principal (client cert): " + conn.getLocalPrincipal());
                } else {
                    System.out.println("[hello-client]   No local client certificate presented (server likely did not request it)");
                }
                Certificate[] localChain = conn.getLocalCertificates();
                if (localChain != null) {
                    for (int i = 0; i < localChain.length; i++) {
                        if (localChain[i] instanceof X509Certificate) {
                            X509Certificate xc = (X509Certificate) localChain[i];
                            System.out.println("[hello-client]     [client chain " + i + "] Subject=" + xc.getSubjectX500Principal()
                                    + ", Issuer=" + xc.getIssuerX500Principal()
                                    + ", Serial=" + xc.getSerialNumber());
                        }
                    }
                }
                if (code != 200) {
                    String msg = "Upstream hello-server responded with status " + code;
                    byte[] b = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(502, b.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(b);
                    }
                    return;
                }

                String name;
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    name = br.readLine();
                }

                String body = "Hello, " + name + "!";
                byte[] b = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                exchange.sendResponseHeaders(200, b.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(b);
                }
            } catch (Exception e) {
                e.printStackTrace();
                String msg = "Error calling server: " + e.getMessage();
                byte[] b = msg.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(500, b.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(b);
                }
            }
        }

        private void debugFetchAndValidateServerChain(SSLContext appSslContext) throws Exception {
            SSLSocketFactory trustAllFactory = buildTrustAllFactory();
            try (SSLSocket sock = (SSLSocket) trustAllFactory.createSocket("hello-server", SERVER_PORT)) {
                sock.setSoTimeout(5000);
                sock.startHandshake();
                Certificate[] peer = sock.getSession().getPeerCertificates();
                System.out.println("[hello-client][DIAG] fetched server peer chain length=" + (peer == null ? 0 : peer.length));
                if (peer != null) {
                    for (int i = 0; i < peer.length; i++) {
                        if (peer[i] instanceof X509Certificate) {
                            X509Certificate xc = (X509Certificate) peer[i];
                            System.out.println("[hello-client][DIAG]   chain[" + i + "] " + xc.getSubjectX500Principal()
                                    + " | Issuer=" + xc.getIssuerX500Principal()
                                    + " | Serial=" + xc.getSerialNumber()
                                    + " | SKI=" + thumbprint(xc.getExtensionValue("2.5.29.14"))
                                    + " | fpSHA256=" + sha256(xc.getEncoded()));
                        }
                    }
                }
                // Build/validate path with our app trust store (from appSslContext)
                X509Certificate[] xcs = Arrays.copyOf(peer, peer.length, X509Certificate[].class);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                CertPath certPath = cf.generateCertPath(Arrays.asList(xcs));
                // Extract trust store from our appSslContext by rebuilding the same store
                KeyStore ts = KeyStore.getInstance("JKS");
                ts.load(null, null);
                try (java.io.InputStream is = java.nio.file.Files.newInputStream(java.nio.file.Path.of("/certs/ca-root.cer"))) {
                    X509Certificate ca = (X509Certificate) cf.generateCertificate(is);
                    ts.setCertificateEntry("myca", ca);
                    System.out.println("[hello-client][DIAG] trust anchor fpSHA256=" + sha256(ca.getEncoded()));
                }
                PKIXParameters pkix = new PKIXParameters(ts);
                pkix.setRevocationEnabled(false);
                CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                cpv.validate(certPath, pkix);
                System.out.println("[hello-client][DIAG] CertPath validated OK");
            }
        }

        private SSLSocketFactory buildTrustAllFactory() throws Exception {
            TrustManager[] tms = new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tms, new java.security.SecureRandom());
            return ctx.getSocketFactory();
        }

        private String sha256(byte[] der) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(der);
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        }

        private String thumbprint(byte[] extVal) {
            if (extVal == null || extVal.length == 0) return "null";
            return Base64.getEncoder().encodeToString(extVal);
        }
    }
}
