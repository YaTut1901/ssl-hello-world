package com.example.client;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
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

class ClientCertManager {
    private final Path keystorePath;
    private final char[] keystorePassword;
    private final Path caRootCertPath;
    private final String caUrl;
    private final String clientCn;

    ClientCertManager(Path keystorePath,
                      char[] keystorePassword,
                      Path caRootCertPath,
                      String caUrl,
                      String clientCn) {
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.caRootCertPath = caRootCertPath;
        this.caUrl = caUrl;
        this.clientCn = clientCn;
    }

    public SSLContext ensureKeystoreAndBuildSslContext() throws Exception {
        KeyStore ks;

        if (!Files.exists(keystorePath)) {
            System.out.println("[hello-client] Keystore not found, generating new one...");
            ks = createNewKeystoreFromCa();
        } else {
            ks = KeyStore.getInstance("JKS");
            try (InputStream is = Files.newInputStream(keystorePath)) {
                ks.load(is, keystorePassword);
            }

            X509Certificate cert = (X509Certificate) ks.getCertificate("client");
            if (cert == null) {
                System.out.println("[hello-client] No 'client' cert in keystore, regenerating...");
                ks = createNewKeystoreFromCa();
            } else {
                try {
                    cert.checkValidity(new Date());
                    System.out.println("[hello-client] Existing client cert OK");
                    System.out.println("[hello-client]   Subject: " + cert.getSubjectX500Principal());
                    System.out.println("[hello-client]   Issuer : " + cert.getIssuerX500Principal());
                    System.out.println("[hello-client]   Serial : " + cert.getSerialNumber());
                    System.out.println("[hello-client]   NotBefore: " + cert.getNotBefore() + ", NotAfter: " + cert.getNotAfter());
                } catch (Exception e) {
                    System.out.println("[hello-client] Client cert expired or not yet valid, regenerating...");
                    ks = createNewKeystoreFromCa();
                }
            }
        }

        return buildSslContextFromKeyStore(ks);
    }

    private KeyStore createNewKeystoreFromCa() throws Exception {
        KeyPair keyPair = generateRsaKeyPair(2048);

        X500Name subject = new X500Name("CN=" + clientCn + ", O=MyOrg, C=UA");
        PKCS10CertificationRequest csr = buildCsr(subject, keyPair);

        byte[] certDer = requestCertFromCa(csr);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate clientCert;
        try (InputStream is = new ByteArrayInputStream(certDer)) {
            clientCert = (X509Certificate) cf.generateCertificate(is);
        }

        // Load CA cert (not included in key entry chain; used by server via its trust store)
        try (InputStream is = Files.newInputStream(caRootCertPath)) {
            cf.generateCertificate(is);
        }

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);

        Certificate[] chain = new Certificate[]{clientCert};
        ks.setKeyEntry("client", keyPair.getPrivate(), keystorePassword, chain);

        try (OutputStream os = Files.newOutputStream(keystorePath)) {
            ks.store(os, keystorePassword);
        }

        System.out.println("[hello-client] New client certificate issued");
        System.out.println("[hello-client]   Subject: " + clientCert.getSubjectX500Principal());
        System.out.println("[hello-client]   Issuer : " + clientCert.getIssuerX500Principal());
        System.out.println("[hello-client]   Serial : " + clientCert.getSerialNumber());
        System.out.println("[hello-client]   NotBefore: " + clientCert.getNotBefore() + ", NotAfter: " + clientCert.getNotAfter());
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
            System.out.println("[hello-client] Loaded CA root into trust store");
            System.out.println("[hello-client]   CA Subject: " + caCert.getSubjectX500Principal());
            System.out.println("[hello-client]   CA Issuer : " + caCert.getIssuerX500Principal());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustManagers = tmf.getTrustManagers();
        System.out.println("[hello-client] TrustManagerFactory algorithm: " + tmf.getAlgorithm());
        for (TrustManager tm : trustManagers) {
            if (tm instanceof X509TrustManager) {
                X509TrustManager xtm = (X509TrustManager) tm;
                X509Certificate[] issuers = xtm.getAcceptedIssuers();
                System.out.println("[hello-client] Accepted issuers count: " + (issuers == null ? 0 : issuers.length));
                if (issuers != null) {
                    for (int i = 0; i < issuers.length; i++) {
                        System.out.println("[hello-client]   Issuer[" + i + "]: " + issuers[i].getSubjectX500Principal());
                    }
                }
            }
        }
        sslContext.init(kmf.getKeyManagers(), trustManagers, new SecureRandom());
        System.out.println("[hello-client] SSLContext initialized with client KeyManagers and CA TrustManagers");
        return sslContext;
    }
}


