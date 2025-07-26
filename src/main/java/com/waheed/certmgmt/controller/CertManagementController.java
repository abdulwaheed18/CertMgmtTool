package com.waheed.certmgmt.controller;

import com.waheed.certmgmt.service.KeystoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * REST Controller for Certificate and Keystore Management.
 */
@RestController
@RequestMapping("/api/v1/keystore")
@CrossOrigin(origins = "*") // Allow all origins for local development
public class CertManagementController {

    @Autowired
    private KeystoreService keystoreService;

    private final Map<String, KeyStore> activeKeystores = new ConcurrentHashMap<>();
    private final Map<String, String> keystorePasswords = new ConcurrentHashMap<>();

    private KeyStore getKeystoreForSession(String sessionId) {
        KeyStore ks = activeKeystores.get(sessionId);
        if (ks == null) {
            throw new IllegalStateException("No active keystore found for this session. Please upload or create one.");
        }
        return ks;
    }

    @PostMapping("/upload")
    public ResponseEntity<?> handleKeystoreUpload(@RequestParam("keystoreFile") MultipartFile file,
                                                  @RequestParam("keystorePassword") String password,
                                                  @RequestParam("sessionId") String sessionId) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Please select a keystore file."));
        }
        try {
            KeyStore ks = keystoreService.loadKeyStore(file.getBytes(), password);
            activeKeystores.put(sessionId, ks);
            keystorePasswords.put(sessionId, password);
            return ResponseEntity.ok(keystoreService.listCertificates(ks));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Failed to load keystore: " + e.getMessage()));
        }
    }

    @PostMapping("/create")
    public ResponseEntity<?> createNewKeystore(@RequestBody Map<String, String> payload) {
        String password = payload.get("password");
        String sessionId = payload.get("sessionId");
        if (password == null || sessionId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Password and sessionId are required."));
        }
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, password.toCharArray());
            activeKeystores.put(sessionId, ks);
            keystorePasswords.put(sessionId, password);
            return ResponseEntity.ok(keystoreService.listCertificates(ks));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Error creating new keystore: " + e.getMessage()));
        }
    }

    @PostMapping("/create-keypair")
    public ResponseEntity<?> createKeyPair(@RequestBody Map<String, Object> payload) {
        try {
            String sessionId = (String) payload.get("sessionId");
            KeyStore ks = getKeystoreForSession(sessionId);

            @SuppressWarnings("unchecked")
            Map<String, String> subjectDetails = (Map<String, String>) payload.get("subjectDetails");

            keystoreService.createKeyPair(ks,
                    (String) payload.get("alias"),
                    (String) payload.get("keyPassword"),
                    subjectDetails,
                    Integer.parseInt((String) payload.get("keySize")),
                    (String) payload.get("sigAlg"));
            return ResponseEntity.ok(keystoreService.listCertificates(ks));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Error creating key pair: " + e.getMessage()));
        }
    }

    @GetMapping("/export-cert/{alias}")
    public ResponseEntity<?> exportCertificate(@PathVariable String alias, @RequestParam String format, @RequestParam String sessionId) {
        try {
            KeyStore ks = getKeystoreForSession(sessionId);
            byte[] certBytes = keystoreService.exportCertificate(ks, alias, format);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + alias + "." + (format.equals("pem") ? "pem" : "cer") + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(certBytes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Error exporting certificate: " + e.getMessage()));
        }
    }

    @PostMapping("/export-private-key")
    public ResponseEntity<?> exportPrivateKey(@RequestBody Map<String, String> payload) {
        try {
            String sessionId = payload.get("sessionId");
            String alias = payload.get("alias");
            String keyPassword = payload.get("keyPassword");
            String encryptionPassword = payload.get("encryptionPassword");

            KeyStore ks = getKeystoreForSession(sessionId);
            byte[] keyBytes = keystoreService.exportPrivateKey(ks, alias, keyPassword, encryptionPassword);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + alias + "_key.pem\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(keyBytes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Error exporting private key: " + e.getMessage()));
        }
    }

    @DeleteMapping("/entry/{alias}")
    public ResponseEntity<?> deleteEntry(@PathVariable String alias, @RequestParam String sessionId) {
        try {
            KeyStore ks = getKeystoreForSession(sessionId);
            keystoreService.deleteEntry(ks, alias);
            return ResponseEntity.ok(keystoreService.listCertificates(ks));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Error deleting entry: " + e.getMessage()));
        }
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadKeystore(@RequestParam String sessionId) {
        try {
            KeyStore ks = getKeystoreForSession(sessionId);
            String password = keystorePasswords.get(sessionId);
            byte[] keystoreBytes = keystoreService.saveKeyStore(ks, password);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"keystore.jks\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(keystoreBytes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error saving keystore: " + e.getMessage()).getBytes());
        }
    }
}