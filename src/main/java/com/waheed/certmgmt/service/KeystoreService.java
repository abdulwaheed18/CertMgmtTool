package com.waheed.certmgmt.service;

import com.waheed.certmgmt.model.CertificateDetails;
import com.waheed.certmgmt.model.KeyPairDetails;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator; // Corrected import
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
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
import java.util.stream.Collectors;

@Service
public class KeystoreService {

    private static final String DEFAULT_KEYSTORE_TYPE = "JKS";
    private static final String BC_PROVIDER = "BC";

    static {
        // Add Bouncy Castle security provider if not already present
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Loads a JKS keystore from a byte array.
     * @param keystoreData The byte array of the JKS file content.
     * @param password The keystore password.
     * @return The loaded KeyStore object.
     * @throws Exception if loading fails.
     */
    public KeyStore loadKeyStore(byte[] keystoreData, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
        try (ByteArrayInputStream bis = new ByteArrayInputStream(keystoreData)) {
            ks.load(bis, password.toCharArray());
        }
        return ks;
    }

    /**
     * Saves the KeyStore to a byte array.
     * @param ks The KeyStore to save.
     * @param password The keystore password.
     * @return The byte array representing the JKS file content.
     * @throws Exception if saving fails.
     */
    public byte[] saveKeyStore(KeyStore ks, String password) throws Exception {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            ks.store(bos, password.toCharArray());
            return bos.toByteArray();
        }
    }

    /**
     * Lists all certificates and key entries in the keystore.
     * @param ks The KeyStore to list entries from.
     * @return A list of CertificateDetails.
     * @throws KeyStoreException if an error occurs while accessing the keystore.
     * @throws NoSuchAlgorithmException if a required cryptographic algorithm is not available.
     * @throws CertificateException if a certificate cannot be processed.
     */
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

    /**
     * Creates a new RSA key pair and a self-signed X.509 certificate for it, then stores it in the keystore.
     * @param ks The KeyStore to add the key pair to.
     * @param alias The alias for the new key pair entry.
     * @param keyPassword The password for the private key.
     * @param commonName The Common Name (CN) for the self-signed certificate.
     * @param keySize The size of the RSA key in bits (e.g., 2048).
     * @return Details of the newly created key pair.
     * @throws Exception if key pair generation or certificate creation fails.
     */
    public KeyPairDetails createKeyPair(KeyStore ks, String alias, String keyPassword, String commonName, int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Create a self-signed certificate for the new key pair
        X500Name subject = new X500Name("CN=" + commonName);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS)); // Valid for 1 year

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(BC_PROVIDER)
                .build(keyPair.getPrivate());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

        // FIX: Directly call toJcaX509Certificate() on the X509CertificateHolder returned by build()
        X509Certificate cert = certBuilder.build(contentSigner).toJcaX509Certificate();

        ks.setKeyEntry(alias, keyPair.getPrivate(), keyPassword.toCharArray(), new Certificate[]{cert});

        return new KeyPairDetails(alias, commonName, keySize, cert);
    }

    /**
     * Generates a PKCS#10 Certificate Signing Request (CSR) for an existing key entry.
     * @param ks The KeyStore containing the key entry.
     * @param alias The alias of the key entry.
     * @param keyPassword The password for the private key.
     * @param commonName The Common Name (CN) for the CSR subject.
     * @return The CSR in PEM format as a String.
     * @throws Exception if CSR generation fails.
     */
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

    /**
     * Imports a certificate into the keystore. If the alias corresponds to a key entry,
     * it attempts to install it as a reply to that key. Otherwise, it creates a new certificate entry.
     * @param ks The KeyStore to import into.
     * @param alias The alias for the certificate entry.
     * @param certData The byte array of the certificate content (PEM or DER).
     * @param keyPassword The password for the private key, required if importing for a key entry.
     * @throws Exception if import fails.
     */
    public void importCertificate(KeyStore ks, String alias, byte[] certData, String keyPassword) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certData));

        if (ks.containsAlias(alias) && ks.isKeyEntry(alias)) {
            // It's a key entry, so we are importing a reply certificate
            Certificate[] chain = ks.getCertificateChain(alias);
            Certificate[] newChain;
            if (chain != null && chain.length > 0) {
                newChain = new Certificate[chain.length + 1];
                newChain[0] = cert; // The new certificate is the first in the chain
                System.arraycopy(chain, 0, newChain, 1, chain.length);
            } else {
                newChain = new Certificate[]{cert};
            }
            ks.setKeyEntry(alias, ks.getKey(alias, keyPassword.toCharArray()), keyPassword.toCharArray(), newChain);
        } else {
            // It's a new certificate entry
            ks.setCertificateEntry(alias, cert);
        }
    }

    /**
     * Exports a certificate from the keystore into various formats.
     * @param ks The KeyStore to export from.
     * @param alias The alias of the certificate to export.
     * @param format The desired format: "der", "pem", or "pkcs7".
     * @return The certificate content as a byte array.
     * @throws Exception if export fails or format is unsupported.
     */
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

    /**
     * Exports the private key (PKCS#8 encrypted or unencrypted) and public key
     * associated with a key entry in PEM format.
     * @param ks The KeyStore to export from.
     * @param alias The alias of the key entry.
     * @param keyPassword The password for the private key (used for encryption if provided).
     * @return A map where keys are filenames (e.g., "privateKey.pem", "publicKey.pem") and values are their content.
     * @throws Exception if export fails.
     */
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

        // Export Private Key (PKCS#8 PEM)
        StringWriter privateKeyWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(privateKeyWriter)) {
            if (keyPassword != null && !keyPassword.isEmpty()) {
                // Encrypt private key with a password
                PemObjectGenerator pkcs8EncryptedGenerator = new JcaPKCS8Generator(privateKey,
                        new JcePEMEncryptorBuilder("AES-256-CBC")
                                .setProvider(BC_PROVIDER)
                                .build(keyPassword.toCharArray()));
                pemWriter.writeObject(pkcs8EncryptedGenerator);
            } else {
                // Export unencrypted PKCS#8 private key
                pemWriter.writeObject(privateKey);
            }
        }
        exported.put("privateKey.pem", privateKeyWriter.toString().getBytes(StandardCharsets.UTF_8));

        // Export Public Key (PEM)
        StringWriter publicKeyWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(publicKeyWriter)) {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", x509Cert.getPublicKey().getEncoded()));
        }
        exported.put("publicKey.pem", publicKeyWriter.toString().getBytes(StandardCharsets.UTF_8));

        return exported;
    }

    /**
     * Deletes an entry (certificate or key entry) from the keystore.
     * @param ks The KeyStore to delete from.
     * @param alias The alias of the entry to delete.
     * @throws KeyStoreException if the alias is not found or deletion fails.
     */
    public void deleteEntry(KeyStore ks, String alias) throws KeyStoreException {
        if (!ks.containsAlias(alias)) {
            throw new KeyStoreException("Alias " + alias + " not found in keystore.");
        }
        ks.deleteEntry(alias);
    }
}