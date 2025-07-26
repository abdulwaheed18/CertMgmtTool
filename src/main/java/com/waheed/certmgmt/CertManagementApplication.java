package com.waheed.certmgmt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching // Enable caching if you plan to use it for results, similar to the original project
public class CertManagementApplication {

    public static void main(String[] args) {
        SpringApplication.run(CertManagementApplication.class, args);
    }
}