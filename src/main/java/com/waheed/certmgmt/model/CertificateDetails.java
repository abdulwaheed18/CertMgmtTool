package com.waheed.certmgmt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateDetails {
    private String alias;
    private String subject;
    private String issuer;
    private Date notBefore;
    private Date notAfter;
    private String serialNumber;
    private String signatureAlgorithm;
    private String entryType; // e.g., "Certificate", "Key Entry"
    private String status; // e.g., "VALID", "EXPIRED", "WARNING"
}