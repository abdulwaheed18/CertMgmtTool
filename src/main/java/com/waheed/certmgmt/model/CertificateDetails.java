package com.waheed.certmgmt.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertificateDetails {
    private String alias;
    private String subject;
    private String issuer;
    private Date notBefore;
    private Date notAfter;
    private String serialNumber;
    private String signatureAlgorithm;
    private String entryType;
    private String status;

    // New fields for the inspector view
    private String version;
    private List<String> keyUsage;
    private List<String> extendedKeyUsage;
    private List<String> subjectAlternativeNames;
    private String publicKeyAlgorithm;
    private int publicKeySize;
    private Map<String, String> thumbprints;


    @JsonInclude(JsonInclude.Include.NON_NULL) // Prevents serialization of null chains
    private List<CertificateDetails> chain;
}