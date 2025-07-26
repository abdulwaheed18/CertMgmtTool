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
 *
 * NOTE: For demonstration purposes, this controller uses a simple in-memory map
 * to store keystores, identified by a session ID. In a real enterprise application,
 * this would be replaced with a secure vault (e.g., HashiCorp Vault, Azure Key Vault)
 * and proper user authentication with JWTs or similar tokens.
 */
@RestController
@RequestMapping("/api/v1/keystore")
@CrossOrigin(origins = "*") // Allow all origins for local development
public class CertManagementController {

    @Autowired
    private KeystoreService keystoreService;

    // WARNING: This is NOT a production-ready way to handle sessions or secrets.
    // It's a simplified mechanism for this demonstration.
    private final Map<String, KeyStore> activeKeystores = new ConcurrentHashMap<>();
    private final Map<String, String> keystorePasswords = new ConcurrentHashMap<>();

    private KeyStore getKeystoreForSession(String sessionId) {
        KeyStore ks = activeKeystores.get(sessionId);
        if (ks == null) {
            throw new IllegalStateException("No active keystore found for this session. Please upload or create one.");
        }
        return ks;
    }

    private String getPasswordForSession(String sessionId) {
        String password = keystorePasswords.get(sessionId);
        if (password == null) {
            throw new IllegalStateException("No keystore password found for this session.");
        }
        return password;
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

    @GetMapping("/certificates")
    public ResponseEntity<?> listCertificates(@RequestParam String sessionId) {
        try {
            return ResponseEntity.ok(keystoreService.listCertificates(getKeystoreForSession(sessionId)));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/create-keypair")
    public ResponseEntity<?> createKeyPair(@RequestBody Map<String, String> payload) {
        try {
            String sessionId = payload.get("sessionId");
            KeyStore ks = getKeystoreForSession(sessionId);
            keystoreService.createKeyPair(ks,
                    payload.get("alias"),
                    payload.get("keyPassword"),
                    payload.get("commonName"),
                    Integer.parseInt(payload.get("keySize")));
            return ResponseEntity.ok(keystoreService.listCertificates(ks));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Error creating key pair: " + e.getMessage()));
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
            String password = getPasswordForSession(sessionId);
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
