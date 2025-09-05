package com.example.authserver.config;

import org.springframework.boot.autoconfigure.cache.CacheManagerCustomizer;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        // Define cache names - clients cache for OAuth2 client configurations
        cacheManager.setCacheNames(java.util.List.of("clients", "users", "tenants"));
        return cacheManager;
    }

    @Bean
    public CacheManagerCustomizer<ConcurrentMapCacheManager> cacheManagerCustomizer() {
        return cacheManager -> {
            // Configure cache settings
            cacheManager.setAllowNullValues(false);
            // Enable dynamic cache creation for additional cache names
            cacheManager.setStoreByValue(true);
        };
    }
}