package com.waheed.certmgmt.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.author")
@Data
public class AppConfigProperties {
    private String name;
    private String email;
    private String title;
    private String github;
    private String linkedin;
    private String blog;
    private String githubRepo;
}