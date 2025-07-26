package com.waheed.certmgmt.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

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
    private String entryType;
    private String status;

    @JsonInclude(JsonInclude.Include.NON_NULL) // Prevents serialization of null chains
    private List<CertificateDetails> chain;
}