package com.waheed.certmgmt.controller;

import com.waheed.certmgmt.model.CertificateDetails;
import com.waheed.certmgmt.model.KeyPairDetails;
import com.waheed.certmgmt.service.KeystoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/certmanagement")
public class CertManagementController {

    @Autowired
    private KeystoreService keystoreService;

    // WARNING: Storing KeyStore and password in class fields is NOT secure for multi-user web applications.
    // This is for demonstration of functionality. For production, consider session-scoped beans,
    // or loading/saving the keystore for each operation, secured with proper authentication/authorization.
    private KeyStore currentKeyStore;
    private String currentKeyStorePassword;

    @GetMapping("")
    public String showCertManagementPage(Model model) {
        model.addAttribute("message", "Upload a JKS Keystore or create a new one.");
        if (currentKeyStore != null) {
            try {
                model.addAttribute("certificates", keystoreService.listCertificates(currentKeyStore));
                model.addAttribute("keystoreLoaded", true);
            } catch (Exception e) {
                model.addAttribute("error", "Error listing certificates: " + e.getMessage());
            }
        } else {
            model.addAttribute("certificates", Collections.emptyList());
            model.addAttribute("keystoreLoaded", false);
        }
        return "certmanagement"; // Corresponds to certmanagement.html
    }

    @PostMapping("/upload")
    public String handleKeystoreUpload(@RequestParam("keystoreFile") MultipartFile file,
                                       @RequestParam("keystorePassword") String password,
                                       RedirectAttributes redirectAttributes) {
        if (file.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "Please select a keystore file to upload.");
            return "redirect:/certmanagement";
        }
        try {
            currentKeyStore = keystoreService.loadKeyStore(file.getBytes(), password);
            currentKeyStorePassword = password; // Store password for subsequent operations
            redirectAttributes.addFlashAttribute("message", "Keystore '" + file.getOriginalFilename() + "' loaded successfully!");
        } catch (Exception e) {
            currentKeyStore = null; // Clear if load fails
            currentKeyStorePassword = null;
            redirectAttributes.addFlashAttribute("error", "Failed to load keystore: " + e.getMessage());
        }
        return "redirect:/certmanagement";
    }

    @PostMapping("/create-keystore")
    public String createNewKeystore(@RequestParam("newKeystorePassword") String newKeystorePassword,
                                    RedirectAttributes redirectAttributes) {
        try {
            currentKeyStore = KeyStore.getInstance("JKS");
            currentKeyStore.load(null, newKeystorePassword.toCharArray()); // Initialize an empty keystore
            currentKeyStorePassword = newKeystorePassword;
            redirectAttributes.addFlashAttribute("message", "New empty keystore created successfully!");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error creating new keystore: " + e.getMessage());
        }
        return "redirect:/certmanagement";
    }

    @GetMapping("/download-keystore")
    public ResponseEntity<byte[]> downloadKeystore() {
        if (currentKeyStore == null || currentKeyStorePassword == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("No keystore loaded or password missing to save.".getBytes());
        }
        try {
            byte[] keystoreBytes = keystoreService.saveKeyStore(currentKeyStore, currentKeyStorePassword);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"mykeystore.jks\"")
                    .contentType(MediaType.parseMediaType("application/x-java-jks"))
                    .body(keystoreBytes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error saving keystore: " + e.getMessage()).getBytes());
        }
    }

    @PostMapping("/create-keypair")
    public String createKeyPair(@RequestParam("alias") String alias,
                                @RequestParam("keyPassword") String keyPassword,
                                @RequestParam("commonName") String commonName,
                                @RequestParam("keySize") int keySize,
                                RedirectAttributes redirectAttributes) {
        if (currentKeyStore == null) {
            redirectAttributes.addFlashAttribute("error", "No keystore loaded. Please upload or create one first.");
            return "redirect:/certmanagement";
        }
        try {
            KeyPairDetails details = keystoreService.createKeyPair(currentKeyStore, alias, keyPassword, commonName, keySize);
            redirectAttributes.addFlashAttribute("message", "Key pair '" + details.getAlias() + "' created and self-signed certificate added.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error creating key pair: " + e.getMessage());
        }
        return "redirect:/certmanagement";
    }

    @GetMapping("/export-csr/{alias}")
    public ResponseEntity<byte[]> exportCsr(@PathVariable String alias,
                                            @RequestParam("keyPassword") String keyPassword,
                                            @RequestParam("commonName") String commonName) {
        if (currentKeyStore == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        try {
            String csrContent = keystoreService.createCSR(currentKeyStore, alias, keyPassword, commonName);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + alias + ".csr\"")
                    .contentType(MediaType.parseMediaType("application/x-x509-csr"))
                    .body(csrContent.getBytes());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error creating CSR: " + e.getMessage()).getBytes());
        }
    }

    @PostMapping("/import-cert")
    public String importCertificate(@RequestParam("alias") String alias,
                                    @RequestParam("certFile") MultipartFile certFile,
                                    @RequestParam(value = "keyPassword", required = false) String keyPassword,
                                    RedirectAttributes redirectAttributes) {
        if (currentKeyStore == null) {
            redirectAttributes.addFlashAttribute("error", "No keystore loaded. Please upload or create one first.");
            return "redirect:/certmanagement";
        }
        if (certFile.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "Please select a certificate file to import.");
            return "redirect:/certmanagement";
        }
        try {
            keystoreService.importCertificate(currentKeyStore, alias, certFile.getBytes(), keyPassword);
            redirectAttributes.addFlashAttribute("message", "Certificate imported successfully for alias '" + alias + "'.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error importing certificate: " + e.getMessage());
        }
        return "redirect:/certmanagement";
    }

    @GetMapping("/export-cert/{alias}")
    public ResponseEntity<byte[]> exportCertificate(@PathVariable String alias, @RequestParam("format") String format) {
        if (currentKeyStore == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        try {
            byte[] certData = keystoreService.exportCertificate(currentKeyStore, alias, format);
            String filename = alias + "." + format.toLowerCase();
            String contentType = "application/octet-stream";
            if ("pem".equalsIgnoreCase(format)) {
                contentType = "application/x-pem-file";
            } else if ("der".equalsIgnoreCase(format)) {
                contentType = "application/pkix-cert";
            } else if ("pkcs7".equalsIgnoreCase(format)) {
                contentType = "application/x-pkcs7-certificates";
            }

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.parseMediaType(contentType))
                    .body(certData);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error exporting certificate: " + e.getMessage()).getBytes());
        }
    }

    @GetMapping("/export-keypair/{alias}")
    public ResponseEntity<byte[]> exportKeyPair(@PathVariable String alias, @RequestParam("keyPassword") String keyPassword) {
        if (currentKeyStore == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        try {
            Map<String, byte[]> exportedFiles = keystoreService.exportKeyPairPem(currentKeyStore, alias, keyPassword);

            // Create a simple zip file for both private and public keys
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(baos)) {
                for (Map.Entry<String, byte[]> entry : exportedFiles.entrySet()) {
                    java.util.zip.ZipEntry zipEntry = new java.util.zip.ZipEntry(entry.getKey());
                    zos.putNextEntry(zipEntry);
                    zos.write(entry.getValue());
                    zos.closeEntry();
                }
            }

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + alias + "-keypair.zip\"")
                    .contentType(MediaType.parseMediaType("application/zip"))
                    .body(baos.toByteArray());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error exporting key pair: " + e.getMessage()).getBytes());
        }
    }

    @PostMapping("/delete-entry/{alias}")
    public String deleteEntry(@PathVariable String alias, RedirectAttributes redirectAttributes) {
        if (currentKeyStore == null) {
            redirectAttributes.addFlashAttribute("error", "No keystore loaded. Please upload or create one first.");
            return "redirect:/certmanagement";
        }
        try {
            keystoreService.deleteEntry(currentKeyStore, alias);
            redirectAttributes.addFlashAttribute("message", "Entry '" + alias + "' deleted successfully.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error deleting entry: " + e.getMessage());
        }
        return "redirect:/certmanagement";
    }
}