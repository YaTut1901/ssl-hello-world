package com.example.ca;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;


public class Utils {

    static KeyPair generateRsaKeyPair(int keySize) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    public static X509Certificate generateCertificate(
            X500Name issuer,
            X500Name subject,
            PublicKey subjectPublicKey,
            PrivateKey signingKey,
            PublicKey issuerPublicKey,
            Duration validity,
            boolean isCa,
            int keyUsageBits,
            KeyPurposeId[] extendedKeyUsages,
            String[] dnsSubjectAltNames) throws Exception {

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter = new Date(now + validity.toMillis());

        BigInteger serial = BigInteger.valueOf(now ^ subjectPublicKey.hashCode());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                subjectPublicKey);

        builder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(isCa));

        if (keyUsageBits != 0) {
            builder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(keyUsageBits));
        }

        // Add Subject Key Identifier (SKI)
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(subjectPublicKey);
        builder.addExtension(Extension.subjectKeyIdentifier, false, ski);

        // Add Authority Key Identifier (AKI) based on issuer public key
        if (issuerPublicKey != null) {
            AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(issuerPublicKey);
            builder.addExtension(Extension.authorityKeyIdentifier, false, aki);
        }

        // Add Extended Key Usage if provided
        if (extendedKeyUsages != null && extendedKeyUsages.length > 0) {
            builder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(extendedKeyUsages));
        }

        // Add Subject Alternative Name (SAN) DNS entries if provided
        if (dnsSubjectAltNames != null && dnsSubjectAltNames.length > 0) {
            GeneralName[] names = new GeneralName[dnsSubjectAltNames.length];
            for (int i = 0; i < dnsSubjectAltNames.length; i++) {
                names[i] = new GeneralName(GeneralName.dNSName, dnsSubjectAltNames[i]);
            }
            GeneralNames gns = new GeneralNames(names);
            builder.addExtension(Extension.subjectAlternativeName, false, gns);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(signingKey);

        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

}
