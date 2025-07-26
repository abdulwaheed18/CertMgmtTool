package com.waheed.certmgmt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509Certificate;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeyPairDetails {
    private String alias;
    private String commonName;
    private int keySize;
    private X509Certificate selfSignedCertificate; // The certificate created with the key pair
}