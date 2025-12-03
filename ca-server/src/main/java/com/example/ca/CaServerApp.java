package com.example.ca;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1String;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

public class CaServerApp {

    private static final String CA_KEYSTORE_PATH = "ca-keystore.jks";
    private static final String CA_KEYSTORE_TYPE = "JKS";
    private static final String CA_ALIAS = "myca";
    private static final char[] CA_PASSWORD = System.getenv("CA_PASSWORD") != null
            ? System.getenv("CA_PASSWORD").toCharArray()
            : new char[0];
    private static final String CA_ROOT_CERT_PATH = "/certs/ca-root.cer";
    private static final String CA_ISSUE_ENDPOINT = System.getenv("CA_ISSUE_ENDPOINT");
    private static final Integer CA_SERVER_PORT = Integer.parseInt(System.getenv("CA_SERVER_PORT"));

    public static void main(String[] args) throws Exception {
        if (CA_ISSUE_ENDPOINT == null) {
            throw new Exception("CA_ISSUE_ENDPOINT is not set!");
        }

        if (CA_SERVER_PORT == null) {
            throw new Exception("CA_SERVER_PORT is not set!");
        }
        
        Security.addProvider(new BouncyCastleProvider());

        ensureCaKeystore();

        HttpServer server = HttpServer.create(new InetSocketAddress(CA_SERVER_PORT), 0);
        server.createContext(CA_ISSUE_ENDPOINT, new IssueHandler());
        server.setExecutor(null);
        System.out.println(String.format("[CA] CA server started on http://localhost:%s", CA_SERVER_PORT));
        server.start();
    }

    private static void ensureCaKeystore() throws Exception {
        if (CA_PASSWORD.length == 0) {
            throw new Exception("CA_PASSWORD is not set!");
        }

        File caFile = new File(CA_KEYSTORE_PATH);
        if (caFile.exists()) {
            System.out.println("[CA] Using existing CA keystore: " + CA_KEYSTORE_PATH);
            return;
        }

        System.out.println("[CA] Generating new root CA...");

        KeyPair caKeyPair = Utils.generateRsaKeyPair(4096);
        X500Name caName = new X500Name("CN=MyDevCA, O=MyOrg, C=UA");

        X509Certificate caCert = Utils.generateCertificate(
                caName,
                caName,
                caKeyPair.getPublic(),
                caKeyPair.getPrivate(),
                caKeyPair.getPublic(),
                Duration.ofDays(365),
                true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign,
                null,
                null);

        KeyStore caKs = KeyStore.getInstance(CA_KEYSTORE_TYPE);
        caKs.load(null, CA_PASSWORD);
        caKs.setKeyEntry(CA_ALIAS, caKeyPair.getPrivate(), CA_PASSWORD, new Certificate[] { caCert });

        try (FileOutputStream fos = new FileOutputStream(CA_KEYSTORE_PATH)) {
            caKs.store(fos, CA_PASSWORD);
        }

        try (FileOutputStream fos = new FileOutputStream(CA_ROOT_CERT_PATH)) {
            fos.write(caCert.getEncoded());
        }

        System.out.println("[CA] Root CA generated. Keystore: " + CA_KEYSTORE_PATH +
                ", root cert: " + CA_ROOT_CERT_PATH +
                ", valid until: " + caCert.getNotAfter());
    }

    static class IssueHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                String pem;
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append('\n');
                    }
                    pem = sb.toString();
                }

                PKCS10CertificationRequest csr;
                try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
                    Object obj = pemParser.readObject();
                    if (!(obj instanceof PKCS10CertificationRequest)) {
                        throw new IllegalArgumentException("Request is not a valid PKCS#10 CSR");
                    }
                    csr = (PKCS10CertificationRequest) obj;
                }

                KeyStore caKs = KeyStore.getInstance(CA_KEYSTORE_TYPE);
                try (FileInputStream fis = new FileInputStream(CA_KEYSTORE_PATH)) {
                    caKs.load(fis, CA_PASSWORD);
                }
                PrivateKey caPrivateKey = (PrivateKey) caKs.getKey(CA_ALIAS, CA_PASSWORD);
                X509Certificate caCert = (X509Certificate) caKs.getCertificate(CA_ALIAS);

                SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
                byte[] encodedPk = pkInfo.getEncoded();
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPk));
                X500Name subject = csr.getSubject();

                // Preserve exact ASN.1 structure of issuer DN to satisfy name-chaining checks
                X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

                // Determine EKU and SAN based on CN
                String cn = extractCommonName(subject);
                KeyPurposeId[] eku = null;
                String[] sans = null;
                if ("hello-server".equalsIgnoreCase(cn)) {
                    eku = new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth };
                    sans = new String[] { "hello-server" };
                } else if ("hello-client".equalsIgnoreCase(cn)) {
                    eku = new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth };
                }

                X509Certificate serverCert = Utils.generateCertificate(
                        issuer,
                        subject,
                        serverPublicKey,
                        caPrivateKey,
                        caCert.getPublicKey(),
                        Duration.ofDays(90),
                        false,
                        KeyUsage.digitalSignature | KeyUsage.keyEncipherment,
                        eku,
                        sans);

                byte[] certDer = serverCert.getEncoded();

                exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
                exchange.sendResponseHeaders(200, certDer.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(certDer);
                }
            } catch (Exception e) {
                e.printStackTrace();
                String msg = "CA CSR error: " + e.getMessage();
                byte[] b = msg.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(500, b.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(b);
                }
            }
        }
    }

    private static String extractCommonName(X500Name name) {
        RDN[] rdns = name.getRDNs(BCStyle.CN);
        if (rdns != null && rdns.length > 0) {
            ASN1Encodable value = rdns[0].getFirst().getValue();
            if (value instanceof ASN1String) {
                return ((ASN1String) value).getString();
            } else {
                return value.toString();
            }
        }
        return null;
    }
}
