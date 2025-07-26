package com.waheed.certmgmt.controller;

import com.waheed.certmgmt.service.KeystoreService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.util.Map;

/**
 * REST Controller for managing all keystore operations.
 * This controller now uses standard Spring HttpSession for session management.
 * FIX: Stores the KeyStore as a byte[] in the session to ensure it is serializable for Redis.
 */
@RestController
@RequestMapping("/api/v1/keystore")
@CrossOrigin(origins = "http://localhost:8080", allowCredentials = "true")
public class CertManagementController {

    // FIX: Changed attribute names to reflect storing bytes instead of the object.
    private static final String KEYSTORE_BYTES_SESSION_ATTR = "KEYSTORE_BYTES_IN_SESSION";
    private static final String PASSWORD_SESSION_ATTR = "KEYSTORE_PASSWORD_IN_SESSION";

    @Autowired
    private KeystoreService keystoreService;

    /**
     * FIX: Reconstructs the KeyStore object from the byte array stored in the session.
     * This is done on-demand for each request that needs the keystore.
     * @param session The current HttpSession.
     * @return The reconstructed KeyStore object.
     */
    private KeyStore getKeystoreFromSession(HttpSession session) throws Exception {
        byte[] keystoreBytes = (byte[]) session.getAttribute(KEYSTORE_BYTES_SESSION_ATTR);
        String password = getPasswordFromSession(session);
        if (keystoreBytes == null) {
            throw new IllegalStateException("No active keystore found for this session. Please upload or create one first.");
        }
        return keystoreService.loadKeyStore(keystoreBytes, password);
    }

    private String getPasswordFromSession(HttpSession session) {
        String password = (String) session.getAttribute(PASSWORD_SESSION_ATTR);
        if (password == null) {
            throw new IllegalStateException("No keystore password found for this session.");
        }
        return password;
    }

    /**
     * Helper method to convert a KeyStore object to a byte array for session storage.
     * @param ks The KeyStore to convert.
     * @param password The password for the keystore.
     * @return A byte array representing the keystore.
     */
    private byte[] keystoreToBytes(KeyStore ks, String password) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ks.store(bos, password.toCharArray());
        return bos.toByteArray();
    }

    private ResponseEntity<?> getDashboardDetails(KeyStore ks) throws Exception {
        Map<String, Object> response = Map.of(
                "certificates", keystoreService.listCertificates(ks),
                "stats", keystoreService.getKeystoreStats(ks)
        );
        return ResponseEntity.ok(response);
    }

    /**
     * FIX: After loading the keystore, it's converted to bytes before being stored in the session.
     */
    @PostMapping("/upload")
    public ResponseEntity<?> handleKeystoreUpload(@RequestParam("keystoreFile") MultipartFile file,
                                                  @RequestParam("keystorePassword") String password,
                                                  HttpSession session) throws Exception {
        KeyStore ks = keystoreService.loadKeyStore(file.getBytes(), password);
        session.setAttribute(KEYSTORE_BYTES_SESSION_ATTR, keystoreToBytes(ks, password));
        session.setAttribute(PASSWORD_SESSION_ATTR, password);
        return getDashboardDetails(ks);
    }

    /**
     * FIX: The newly created empty keystore is converted to bytes before being stored in the session.
     */
    @PostMapping("/create")
    public ResponseEntity<?> createNewKeystore(@RequestBody Map<String, String> payload, HttpSession session) throws Exception {
        String password = payload.get("password");
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, password.toCharArray());
        session.setAttribute(KEYSTORE_BYTES_SESSION_ATTR, keystoreToBytes(ks, password));
        session.setAttribute(PASSWORD_SESSION_ATTR, password);
        return getDashboardDetails(ks);
    }

    /**
     * A generic helper to update the keystore in the session after a modification.
     * @param ks The modified KeyStore object.
     * @param session The current HttpSession.
     */
    private void updateKeystoreInSession(KeyStore ks, HttpSession session) throws Exception {
        String password = getPasswordFromSession(session);
        session.setAttribute(KEYSTORE_BYTES_SESSION_ATTR, keystoreToBytes(ks, password));
    }

    @PostMapping("/update-chain")
    public ResponseEntity<?> updateCertificateChain(@RequestParam("certFile") MultipartFile file,
                                                    @RequestParam("alias") String alias,
                                                    @RequestParam("keyPassword") String keyPassword,
                                                    HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        keystoreService.updateCertificateChain(ks, alias, keyPassword, file.getBytes());
        updateKeystoreInSession(ks, session); // Update session with modified keystore
        return getDashboardDetails(ks);
    }

    @PostMapping("/create-keypair")
    public ResponseEntity<?> createKeyPair(@RequestBody Map<String, Object> payload, HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        @SuppressWarnings("unchecked")
        Map<String, String> subjectDetails = (Map<String, String>) payload.get("subjectDetails");
        keystoreService.createKeyPair(ks,
                (String) payload.get("alias"),
                (String) payload.get("keyPassword"),
                subjectDetails,
                Integer.parseInt((String) payload.get("keySize")),
                (String) payload.get("sigAlg"));
        updateKeystoreInSession(ks, session); // Update session with modified keystore
        return getDashboardDetails(ks);
    }

    @PostMapping("/import-cert")
    public ResponseEntity<?> importCertificate(@RequestParam("certFile") MultipartFile file,
                                               @RequestParam("alias") String alias,
                                               HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        keystoreService.importCertificate(ks, alias, file.getBytes());
        updateKeystoreInSession(ks, session); // Update session with modified keystore
        return getDashboardDetails(ks);
    }

    @GetMapping("/export-cert/{alias}")
    public ResponseEntity<byte[]> exportCertificate(@PathVariable String alias, @RequestParam String format, HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        byte[] certBytes = keystoreService.exportCertificate(ks, alias, format);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + alias + "." + (format.equals("pem") ? "pem" : "cer") + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(certBytes);
    }

    @PostMapping("/generate-csr")
    public ResponseEntity<byte[]> generateCsr(@RequestBody Map<String, String> payload, HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        String alias = payload.get("alias");
        String keyPassword = payload.get("keyPassword");
        byte[] csrBytes = keystoreService.generateCsr(ks, alias, keyPassword);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + alias + ".csr\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(csrBytes);
    }

    @PostMapping("/export-private-key")
    public ResponseEntity<byte[]> exportPrivateKey(@RequestBody Map<String, String> payload, HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        String alias = payload.get("alias");
        String keyPassword = payload.get("keyPassword");
        String encryptionPassword = payload.get("encryptionPassword");
        byte[] keyBytes = keystoreService.exportPrivateKey(ks, alias, keyPassword, encryptionPassword);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + alias + "_key.pem\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(keyBytes);
    }

    @DeleteMapping("/entry/{alias}")
    public ResponseEntity<?> deleteEntry(@PathVariable String alias, HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        keystoreService.deleteEntry(ks, alias);
        updateKeystoreInSession(ks, session); // Update session with modified keystore
        return getDashboardDetails(ks);
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadKeystore(HttpSession session) throws Exception {
        KeyStore ks = getKeystoreFromSession(session);
        String password = getPasswordFromSession(session);
        byte[] keystoreBytes = keystoreToBytes(ks, password);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"keystore.jks\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(keystoreBytes);
    }
}
