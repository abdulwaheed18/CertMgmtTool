package com.waheed.certmgmt.controller;

import com.waheed.certmgmt.config.AppConfigProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class GlobalControllerAdvice {

    private final AppConfigProperties appConfigProperties;

    @Autowired
    public GlobalControllerAdvice(AppConfigProperties appConfigProperties) {
        this.appConfigProperties = appConfigProperties;
    }

    @ModelAttribute("appConfig")
    public AppConfigProperties getAppConfigProperties() {
        return appConfigProperties;
    }
}