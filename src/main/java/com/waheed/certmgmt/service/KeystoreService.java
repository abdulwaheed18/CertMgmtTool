package com.waheed.certmgmt.service;

import com.waheed.certmgmt.model.CertificateDetails;
import com.waheed.certmgmt.model.KeyPairDetails;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

@Service
public class KeystoreService {

    private static final String DEFAULT_KEYSTORE_TYPE = "JKS";
    private static final String BC_PROVIDER = "BC";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public KeyStore loadKeyStore(byte[] keystoreData, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
        try (ByteArrayInputStream bis = new ByteArrayInputStream(keystoreData)) {
            ks.load(bis, password.toCharArray());
        }
        return ks;
    }

    public byte[] saveKeyStore(KeyStore ks, String password) throws Exception {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            ks.store(bos, password.toCharArray());
            return bos.toByteArray();
        }
    }

    private String getCertificateStatus(X509Certificate cert) {
        Date now = new Date();
        if (cert.getNotAfter().before(now)) {
            return "EXPIRED";
        }
        if (cert.getNotAfter().before(Date.from(Instant.now().plus(30, ChronoUnit.DAYS)))) {
            return "WARNING";
        }
        return "VALID";
    }

    public List<CertificateDetails> listCertificates(KeyStore ks) throws Exception {
        List<CertificateDetails> certDetailsList = new ArrayList<>();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            CertificateDetails details = buildCertificateDetails(ks, alias);
            if (details != null) {
                certDetailsList.add(details);
            }
        }
        return certDetailsList;
    }

    private CertificateDetails buildCertificateDetails(KeyStore ks, String alias) throws Exception {
        String entryType;
        Certificate[] chain;

        if (ks.isKeyEntry(alias)) {
            entryType = "Key Pair (Private Key & Certificate)";
            chain = ks.getCertificateChain(alias);
        } else if (ks.isCertificateEntry(alias)) {
            entryType = "Trusted Certificate";
            chain = new Certificate[]{ks.getCertificate(alias)};
        } else {
            return null; // Skip unknown entry types
        }

        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
            return new CertificateDetails(alias, "N/A", "N/A", null, null, "N/A", "N/A", entryType, "UNKNOWN", null);
        }

        X509Certificate primaryCert = (X509Certificate) chain[0];
        List<CertificateDetails> chainDetails = new ArrayList<>();
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate x509Cert) {
                chainDetails.add(new CertificateDetails(
                        alias,
                        x509Cert.getSubjectX500Principal().getName(),
                        x509Cert.getIssuerX500Principal().getName(),
                        x509Cert.getNotBefore(),
                        x509Cert.getNotAfter(),
                        x509Cert.getSerialNumber().toString(),
                        x509Cert.getSigAlgName(),
                        entryType,
                        getCertificateStatus(x509Cert),
                        null
                ));
            }
        }

        return new CertificateDetails(
                alias,
                primaryCert.getSubjectX500Principal().getName(),
                primaryCert.getIssuerX500Principal().getName(),
                primaryCert.getNotBefore(),
                primaryCert.getNotAfter(),
                primaryCert.getSerialNumber().toString(),
                primaryCert.getSigAlgName(),
                entryType,
                getCertificateStatus(primaryCert),
                chainDetails
        );
    }

    public KeyPairDetails createKeyPair(KeyStore ks, String alias, String keyPassword, Map<String, String> subjectDetails, int keySize, String sigAlg) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, subjectDetails.get("CN"));
        nameBuilder.addRDN(BCStyle.OU, subjectDetails.get("OU"));
        nameBuilder.addRDN(BCStyle.O, subjectDetails.get("O"));
        nameBuilder.addRDN(BCStyle.L, subjectDetails.get("L"));
        nameBuilder.addRDN(BCStyle.ST, subjectDetails.get("ST"));
        nameBuilder.addRDN(BCStyle.C, subjectDetails.get("C"));
        X500Name subject = nameBuilder.build();

        BigInteger serial = new BigInteger(160, new SecureRandom());
        Date notBefore = new Date();
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(BC_PROVIDER).build(keyPair.getPrivate());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);

        ks.setKeyEntry(alias, keyPair.getPrivate(), keyPassword.toCharArray(), new Certificate[]{cert});
        return new KeyPairDetails(alias, subjectDetails.get("CN"), keySize, cert);
    }

    public void importCertificate(KeyStore ks, String alias, byte[] certData) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certData));
        ks.setCertificateEntry(alias, cert);
    }

    public byte[] exportCertificate(KeyStore ks, String alias, String format) throws Exception {
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new KeyStoreException("No certificate found for alias: " + alias);
        }
        return switch (format.toLowerCase()) {
            case "der" -> cert.getEncoded();
            case "pem" -> {
                StringWriter sw = new StringWriter();
                try (PemWriter pw = new PemWriter(sw)) {
                    pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
                }
                yield sw.toString().getBytes(StandardCharsets.UTF_8);
            }
            default -> throw new IllegalArgumentException("Unsupported export format: " + format);
        };
    }

    public byte[] exportPrivateKey(KeyStore ks, String alias, String keyPassword, String encryptionPassword) throws Exception {
        Key key = ks.getKey(alias, keyPassword.toCharArray());
        if (!(key instanceof PrivateKey privateKey)) {
            throw new KeyStoreException("Alias '" + alias + "' does not contain a private key.");
        }

        StringWriter privateKeyWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(privateKeyWriter)) {
            if (encryptionPassword != null && !encryptionPassword.isEmpty()) {
                OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                        .setProvider(BC_PROVIDER)
                        .build(encryptionPassword.toCharArray());
                JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, encryptor);
                pemWriter.writeObject(pkcs8Generator);
            } else {
                pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            }
        }
        return privateKeyWriter.toString().getBytes(StandardCharsets.UTF_8);
    }

    public void deleteEntry(KeyStore ks, String alias) throws KeyStoreException {
        if (!ks.containsAlias(alias)) {
            throw new KeyStoreException("Alias '" + alias + "' not found in keystore.");
        }
        ks.deleteEntry(alias);
    }
}