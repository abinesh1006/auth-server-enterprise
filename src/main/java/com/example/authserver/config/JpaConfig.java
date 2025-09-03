package com.example.authserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableJpaRepositories(basePackages = "com.example.authserver")
@EnableTransactionManagement
public class JpaConfig {
    // This configuration ensures JPA repositories are properly scanned and configured
}