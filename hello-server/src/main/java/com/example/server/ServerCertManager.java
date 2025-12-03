package com.example.server;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;

class ServerCertManager {
    private final Path keystorePath;
    private final char[] keystorePassword;
    private final Path caRootCertPath;
    private final String caUrl;
    private final String serverCn;

    ServerCertManager(Path keystorePath,
                      char[] keystorePassword,
                      Path caRootCertPath,
                      String caUrl,
                      String serverCn) {
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.caRootCertPath = caRootCertPath;
        this.caUrl = caUrl;
        this.serverCn = serverCn;
    }

    public SSLContext ensureKeystoreAndBuildSslContext() throws Exception {
        KeyStore ks;

        if (!Files.exists(keystorePath)) {
            System.out.println("[hello-server] Keystore not found, generating new one...");
            ks = createNewKeystoreFromCa();
        } else {
            ks = KeyStore.getInstance("JKS");
            try (InputStream is = Files.newInputStream(keystorePath)) {
                ks.load(is, keystorePassword);
            }

            X509Certificate cert = (X509Certificate) ks.getCertificate("server");
            if (cert == null) {
                System.out.println("[hello-server] No 'server' cert in keystore, regenerating...");
                ks = createNewKeystoreFromCa();
            } else {
                try {
                    cert.checkValidity(new Date());
                    System.out.println("[hello-server] Existing server cert OK");
                    System.out.println("[hello-server]   Subject: " + cert.getSubjectX500Principal());
                    System.out.println("[hello-server]   Issuer : " + cert.getIssuerX500Principal());
                    System.out.println("[hello-server]   Serial : " + cert.getSerialNumber());
                    System.out.println("[hello-server]   NotBefore: " + cert.getNotBefore() + ", NotAfter: " + cert.getNotAfter());
                } catch (Exception e) {
                    System.out.println("[hello-server] Server cert expired or not yet valid, regenerating...");
                    ks = createNewKeystoreFromCa();
                }
            }
        }

        return buildSslContextFromKeyStore(ks);
    }

    private KeyStore createNewKeystoreFromCa() throws Exception {
        KeyPair keyPair = generateRsaKeyPair(2048);

        X500Name subject = new X500Name("CN=" + serverCn + ", O=MyOrg, C=UA");
        PKCS10CertificationRequest csr = buildCsr(subject, keyPair);

        byte[] certDer = requestCertFromCa(csr);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert;
        try (InputStream is = new ByteArrayInputStream(certDer)) {
            serverCert = (X509Certificate) cf.generateCertificate(is);
        }

        // Load CA cert (not included in key entry chain; used by clients via their trust store)
        try (InputStream is = Files.newInputStream(caRootCertPath)) {
            cf.generateCertificate(is);
        }

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);

        // Include CA certificate in the served chain (helps clients without cached CA)
        X509Certificate caCert;
        try (InputStream is = Files.newInputStream(caRootCertPath)) {
            caCert = (X509Certificate) cf.generateCertificate(is);
        }
        Certificate[] chain = new Certificate[]{serverCert, caCert};
        ks.setKeyEntry("server", keyPair.getPrivate(), keystorePassword, chain);

        try (OutputStream os = Files.newOutputStream(keystorePath)) {
            ks.store(os, keystorePassword);
        }

        System.out.println("[hello-server] New server certificate issued");
        System.out.println("[hello-server]   Subject: " + serverCert.getSubjectX500Principal());
        System.out.println("[hello-server]   Issuer : " + serverCert.getIssuerX500Principal());
        System.out.println("[hello-server]   Serial : " + serverCert.getSerialNumber());
        System.out.println("[hello-server]   NotBefore: " + serverCert.getNotBefore() + ", NotAfter: " + serverCert.getNotAfter());
        return ks;
    }

    private KeyPair generateRsaKeyPair(int size) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    private PKCS10CertificationRequest buildCsr(X500Name subject, KeyPair keyPair) throws Exception {
        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());
        return csrBuilder.build(signer);
    }

    private byte[] requestCertFromCa(PKCS10CertificationRequest csr) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(csr);
        }
        String pem = sw.toString();

        URL url = URI.create(caUrl).toURL();

        int maxAttempts = 10;
        int attempt = 0;
        IOException lastException = null;

        while (attempt < maxAttempts) {
            attempt++;
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout((int) Duration.ofSeconds(5).toMillis());
            conn.setReadTimeout((int) Duration.ofSeconds(10).toMillis());
            conn.setRequestProperty("Content-Type", "application/pkcs10");

            try {
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(pem.getBytes(StandardCharsets.US_ASCII));
                }

                int code = conn.getResponseCode();
                if (code != 200) {
                    String resp = readAllSafely(conn.getErrorStream());
                    throw new IOException("CA responded with status " + code + ": " + resp);
                }

                try (InputStream is = conn.getInputStream();
                     ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                    byte[] buf = new byte[4096];
                    int read;
                    while ((read = is.read(buf)) != -1) {
                        bos.write(buf, 0, read);
                    }
                    return bos.toByteArray();
                }
            } catch (ConnectException e) {
                lastException = e;
                if (attempt >= maxAttempts) {
                    throw e;
                }
                try {
                    Thread.sleep(1000L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while waiting to retry CA connection", ie);
                }
            }
        }

        throw new IOException("Failed to contact CA after " + maxAttempts + " attempts", lastException);
    }

    private String readAllSafely(InputStream is) throws IOException {
        if (is == null) return "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }

    private SSLContext buildSslContextFromKeyStore(KeyStore ks)
            throws NoSuchAlgorithmException, KeyStoreException,
                   UnrecoverableKeyException, KeyManagementException, IOException, CertificateException {

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keystorePassword);

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = Files.newInputStream(caRootCertPath)) {
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(is);
            trustStore.setCertificateEntry("myca", caCert);
            System.out.println("[hello-server] Loaded CA root into trust store");
            System.out.println("[hello-server]   CA Subject: " + caCert.getSubjectX500Principal());
            System.out.println("[hello-server]   CA Issuer : " + caCert.getIssuerX500Principal());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        System.out.println("[hello-server] SSLContext initialized with server KeyManagers and CA TrustManagers");
        return sslContext;
    }
}

