package com.waheed.certmgmt.service;

import com.waheed.certmgmt.model.CertificateDetails;
import com.waheed.certmgmt.model.KeyPairDetails;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
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
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

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
            // This now correctly builds a single object per alias, with the chain inside it.
            CertificateDetails details = buildCertificateDetailsTree(ks, alias);
            if (details != null) {
                certDetailsList.add(details);
            }
        }
        return certDetailsList;
    }

    public Map<String, Integer> getKeystoreStats(KeyStore ks) throws Exception {
        Map<String, Integer> stats = new HashMap<>();
        // The total count is now based on the number of aliases (entries) in the keystore.
        stats.put("total", ks.size());
        stats.put("valid", 0);
        stats.put("warning", 0);
        stats.put("expired", 0);

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.getCertificate(alias);
            if (cert instanceof X509Certificate x509Cert) {
                String status = getCertificateStatus(x509Cert).toLowerCase();
                stats.merge(status, 1, Integer::sum);
            }
        }
        return stats;
    }

    private CertificateDetails buildCertificateDetailsTree(KeyStore ks, String alias) throws Exception {
        Certificate[] chain = ks.getCertificateChain(alias);
        if (chain == null) {
            // It's a trusted certificate entry, not a key entry
            Certificate cert = ks.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                chain = new Certificate[]{cert};
            } else {
                return null; // Not a supported certificate type
            }
        }

        List<CertificateDetails> chainDetails = new ArrayList<>();
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate x509Cert) {
                // Pass the alias to every certificate in the chain for context
                chainDetails.add(buildSingleCertificateDetails(alias, ks, x509Cert));
            }
        }

        if (chainDetails.isEmpty()) return null;

        // The primary certificate is the first one in the chain
        CertificateDetails primaryDetails = chainDetails.get(0);
        // Set the full chain within the primary certificate object
        primaryDetails.setChain(chainDetails);
        return primaryDetails;
    }


    private CertificateDetails buildSingleCertificateDetails(String alias, KeyStore ks, X509Certificate cert) throws Exception {
        // Correctly determine entry type based on alias
        String entryType = ks.isKeyEntry(alias) ? "Key Pair (Private Key & Certificate)" : "Trusted Certificate";

        return CertificateDetails.builder()
                .alias(alias)
                .subject(cert.getSubjectX500Principal().getName())
                .issuer(cert.getIssuerX500Principal().getName())
                .notBefore(cert.getNotBefore())
                .notAfter(cert.getNotAfter())
                .serialNumber(cert.getSerialNumber().toString(16))
                .signatureAlgorithm(cert.getSigAlgName())
                .entryType(entryType)
                .status(getCertificateStatus(cert))
                .version("v" + cert.getVersion())
                .keyUsage(getKeyUsage(cert))
                .extendedKeyUsage(getExtendedKeyUsage(cert))
                .subjectAlternativeNames(getSubjectAlternativeNames(cert))
                .publicKeyAlgorithm(cert.getPublicKey().getAlgorithm())
                .publicKeySize(getPublicKeySize(cert.getPublicKey()))
                .thumbprints(getThumbprints(cert))
                .build();
    }

    private List<String> getKeyUsage(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage == null) return Collections.emptyList();
        List<String> uses = new ArrayList<>();
        if (keyUsage[0]) uses.add("Digital Signature");
        if (keyUsage[1]) uses.add("Non-Repudiation");
        if (keyUsage[2]) uses.add("Key Encipherment");
        if (keyUsage[3]) uses.add("Data Encipherment");
        if (keyUsage[4]) uses.add("Key Agreement");
        if (keyUsage[5]) uses.add("Key Cert Sign");
        if (keyUsage[6]) uses.add("CRL Sign");
        if (keyUsage[7]) uses.add("Encipher Only");
        if (keyUsage[8]) uses.add("Decipher Only");
        return uses;
    }

    private List<String> getExtendedKeyUsage(X509Certificate cert) throws CertificateParsingException {
        List<String> extKeyUsage = cert.getExtendedKeyUsage();
        if (extKeyUsage == null) return Collections.emptyList();

        return extKeyUsage.stream()
                .map(oid -> {
                    if (KeyPurposeId.id_kp_serverAuth.getId().equals(oid)) return "TLS Web Server Authentication";
                    if (KeyPurposeId.id_kp_clientAuth.getId().equals(oid)) return "TLS Web Client Authentication";
                    if (KeyPurposeId.id_kp_codeSigning.getId().equals(oid)) return "Code Signing";
                    if (KeyPurposeId.id_kp_emailProtection.getId().equals(oid)) return "Email Protection";
                    if (KeyPurposeId.id_kp_timeStamping.getId().equals(oid)) return "Time Stamping";
                    if (KeyPurposeId.id_kp_OCSPSigning.getId().equals(oid)) return "OCSP Signing";
                    return oid; // Fallback to OID
                })
                .collect(Collectors.toList());
    }

    private List<String> getSubjectAlternativeNames(X509Certificate cert) throws CertificateParsingException {
        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        if (sans == null) return Collections.emptyList();
        List<String> names = new ArrayList<>();
        for (List<?> san : sans) {
            Integer type = (Integer) san.get(0);
            String value = san.get(1).toString();
            String prefix = switch (type) {
                case 0 -> "Other Name";
                case 1 -> "RFC 822 Name";
                case 2 -> "DNS Name";
                case 4 -> "Directory Name";
                case 6 -> "URI";
                case 7 -> "IP Address";
                default -> "Unknown";
            };
            names.add(prefix + ": " + value);
        }
        return names;
    }

    private int getPublicKeySize(PublicKey key) {
        if (key instanceof RSAPublicKey rsaKey) {
            return rsaKey.getModulus().bitLength();
        }
        // Add support for other key types if needed
        return 0;
    }

    private Map<String, String> getThumbprints(X509Certificate cert) throws Exception {
        Map<String, String> thumbprints = new HashMap<>();
        byte[] derCert = cert.getEncoded();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        thumbprints.put("SHA-1", bytesToHex(sha1.digest(derCert)));
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        thumbprints.put("SHA-256", bytesToHex(sha256.digest(derCert)));
        return thumbprints;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
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
        if (ks.containsAlias(alias)) {
            throw new KeyStoreException("Alias '" + alias + "' already exists. Use 'Update Chain' for existing key pairs or choose a new alias.");
        }
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certData));
        ks.setCertificateEntry(alias, cert);
    }

    public void updateCertificateChain(KeyStore ks, String alias, String keyPassword, byte[] certData) throws Exception {
        if (!ks.isKeyEntry(alias)) {
            throw new KeyStoreException("Alias '" + alias + "' is not a key pair entry. This function can only update chains for key pairs.");
        }

        Key privateKey = ks.getKey(alias, keyPassword.toCharArray());
        if (privateKey == null) {
            throw new UnrecoverableKeyException("Could not retrieve private key for alias '" + alias + "'. Check the key password.");
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        Collection<? extends Certificate> newChain = certFactory.generateCertificates(new ByteArrayInputStream(certData));

        if (newChain.isEmpty()) {
            throw new IllegalArgumentException("The provided file does not contain any certificates.");
        }

        ks.setKeyEntry(alias, privateKey, keyPassword.toCharArray(), newChain.toArray(new Certificate[0]));
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

    public byte[] generateCsr(KeyStore ks, String alias, String keyPassword) throws Exception {
        Key key = ks.getKey(alias, keyPassword.toCharArray());
        if (!(key instanceof PrivateKey privateKey)) {
            throw new KeyStoreException("Alias '" + alias + "' does not contain a private key.");
        }
        PublicKey publicKey = ks.getCertificate(alias).getPublicKey();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        X500Name subject = new X500Name(cert.getSubjectX500Principal().getName());

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(privateKey);
        var csr = p10Builder.build(signer);

        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(csr);
        }
        return sw.toString().getBytes(StandardCharsets.UTF_8);
    }

    public byte[] exportPrivateKey(KeyStore ks, String alias, String keyPassword, String encryptionPassword) throws Exception {
        Key key = ks.getKey(alias, keyPassword.toCharArray());
        if (!(key instanceof PrivateKey privateKey)) {
            throw new KeyStoreException("Alias '" + alias + "' does not contain a private key.");
        }

        StringWriter privateKeyWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(privateKeyWriter)) {
            if (encryptionPassword != null && !encryptionPassword.isEmpty()) {
                // Use a modern and secure encryption algorithm like AES-256-CBC
                OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                        .setProvider(BC_PROVIDER)
                        .build(encryptionPassword.toCharArray());
                JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, encryptor);
                pemWriter.writeObject(pkcs8Generator);
            } else {
                // Unencrypted private key
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