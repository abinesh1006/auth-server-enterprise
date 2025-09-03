package com.example.authserver.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;

import javax.sql.DataSource;

@Configuration
public class ApplicationShutdownConfig {

    @Autowired
    private DataSource dataSource;

    @EventListener
    public void handleContextClosed(ContextClosedEvent event) {
        // Ensure HikariCP pool is properly closed to prevent memory leaks
        if (dataSource instanceof HikariDataSource) {
            HikariDataSource hikariDataSource = (HikariDataSource) dataSource;
            if (!hikariDataSource.isClosed()) {
                hikariDataSource.close();
            }
        }
    }
}