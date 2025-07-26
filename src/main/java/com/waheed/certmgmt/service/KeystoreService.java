package com.waheed.certmgmt.service;

import com.waheed.certmgmt.model.CertificateDetails;
import com.waheed.certmgmt.model.KeyPairDetails;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder; // <-- CORRECT IMPORT
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

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

    public List<CertificateDetails> listCertificates(KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, CertificateException {
        List<CertificateDetails> certDetailsList = new ArrayList<>();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isCertificateEntry(alias)) {
                Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate x509Cert) {
                    certDetailsList.add(new CertificateDetails(
                            alias,
                            x509Cert.getSubjectX500Principal().getName(),
                            x509Cert.getIssuerX500Principal().getName(),
                            x509Cert.getNotBefore(),
                            x509Cert.getNotAfter(),
                            x509Cert.getSerialNumber().toString(),
                            x509Cert.getSigAlgName(),
                            "Certificate"
                    ));
                }
            } else if (ks.isKeyEntry(alias)) {
                Certificate[] chain = ks.getCertificateChain(alias);
                if (chain != null && chain.length > 0) {
                    X509Certificate x509Cert = (X509Certificate) chain[0];
                    certDetailsList.add(new CertificateDetails(
                            alias,
                            x509Cert.getSubjectX500Principal().getName(),
                            x509Cert.getIssuerX500Principal().getName(),
                            x509Cert.getNotBefore(),
                            x509Cert.getNotAfter(),
                            x509Cert.getSerialNumber().toString(),
                            x509Cert.getSigAlgName(),
                            "Key Entry (with Certificate)"
                    ));
                } else {
                    certDetailsList.add(new CertificateDetails(
                            alias,
                            "N/A", "N/A", null, null, "N/A", "N/A", "Key Entry (no Certificate)"
                    ));
                }
            }
        }
        return certDetailsList;
    }

    public KeyPairDetails createKeyPair(KeyStore ks, String alias, String keyPassword, String commonName, int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=" + commonName);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(BC_PROVIDER)
                .build(keyPair.getPrivate());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(certHolder);

        ks.setKeyEntry(alias, keyPair.getPrivate(), keyPassword.toCharArray(), new Certificate[]{cert});

        return new KeyPairDetails(alias, commonName, keySize, cert);
    }

    public String createCSR(KeyStore ks, String alias, String keyPassword, String commonName) throws Exception {
        if (!ks.containsAlias(alias) || !ks.isKeyEntry(alias)) {
            throw new KeyStoreException("Alias " + alias + " does not exist or is not a key entry.");
        }
        Key key = ks.getKey(alias, keyPassword.toCharArray());
        if (!(key instanceof PrivateKey privateKey)) {
            throw new KeyStoreException("Alias " + alias + " does not contain a private key.");
        }

        X500Name subject = new X500Name("CN=" + commonName);
        JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, ks.getCertificate(alias).getPublicKey());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC_PROVIDER).build(privateKey);
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        StringWriter csrWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(csrWriter)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return csrWriter.toString();
    }

    public void importCertificate(KeyStore ks, String alias, byte[] certData, String keyPassword) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certData));

        if (ks.containsAlias(alias) && ks.isKeyEntry(alias)) {
            Certificate[] chain = ks.getCertificateChain(alias);
            Certificate[] newChain;
            if (chain != null && chain.length > 0) {
                newChain = new Certificate[chain.length + 1];
                newChain[0] = cert;
                System.arraycopy(chain, 0, newChain, 1, chain.length);
            } else {
                newChain = new Certificate[]{cert};
            }
            ks.setKeyEntry(alias, ks.getKey(alias, keyPassword.toCharArray()), keyPassword.toCharArray(), newChain);
        } else {
            ks.setCertificateEntry(alias, cert);
        }
    }

    public byte[] exportCertificate(KeyStore ks, String alias, String format) throws Exception {
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new KeyStoreException("No certificate found for alias: " + alias);
        }

        switch (format.toLowerCase()) {
            case "der":
                return cert.getEncoded();
            case "pem":
                StringWriter sw = new StringWriter();
                try (PemWriter pw = new PemWriter(sw)) {
                    pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
                }
                return sw.toString().getBytes(StandardCharsets.UTF_8);
            case "pkcs7":
                Certificate[] certs = {cert};
                CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(Arrays.asList(certs));
                return certPath.getEncoded("PKCS7");
            default:
                throw new IllegalArgumentException("Unsupported export format: " + format);
        }
    }

    public Map<String, byte[]> exportKeyPairPem(KeyStore ks, String alias, String keyPassword) throws Exception {
        if (!ks.containsAlias(alias) || !ks.isKeyEntry(alias)) {
            throw new KeyStoreException("Alias " + alias + " does not exist or is not a key entry.");
        }

        Key key = ks.getKey(alias, keyPassword.toCharArray());
        if (!(key instanceof PrivateKey privateKey)) {
            throw new KeyStoreException("Alias " + alias + " does not contain a private key.");
        }

        Certificate cert = ks.getCertificate(alias);
        if (!(cert instanceof X509Certificate x509Cert)) {
            throw new KeyStoreException("Alias " + alias + " does not contain an X.509 certificate.");
        }

        Map<String, byte[]> exported = new HashMap<>();

        StringWriter privateKeyWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(privateKeyWriter)) {
            if (keyPassword != null && !keyPassword.isEmpty()) {
                // *** THE FINAL FIX IS HERE ***
                // We now use a valid Algorithm Identifier from PKCSObjectIdentifiers.
                OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                        .setProvider(BC_PROVIDER)
                        .build(keyPassword.toCharArray());
                JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, encryptor);
                pemWriter.writeObject(pkcs8Generator);
            } else {
                pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            }
        }
        exported.put("privateKey.pem", privateKeyWriter.toString().getBytes(StandardCharsets.UTF_8));

        StringWriter publicKeyWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(publicKeyWriter)) {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", x509Cert.getPublicKey().getEncoded()));
        }
        exported.put("publicKey.pem", publicKeyWriter.toString().getBytes(StandardCharsets.UTF_8));

        return exported;
    }

    public void deleteEntry(KeyStore ks, String alias) throws KeyStoreException {
        if (!ks.containsAlias(alias)) {
            throw new KeyStoreException("Alias " + alias + " not found in keystore.");
        }
        ks.deleteEntry(alias);
    }
}