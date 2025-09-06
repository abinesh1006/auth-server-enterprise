package com.example.authserver.security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

@Service
public class WebAuthnRequestStore {

    private static final long TIMEOUT_SECONDS = 300; // 5 minutes
    private Map<String, RequestEntry> requestStore = new ConcurrentHashMap<>();

    public void storeRequest(String username, PublicKeyCredentialCreationOptions options) {
        // Clean up expired entries before adding new one
        cleanupExpiredEntries();
        
        RequestEntry entry = new RequestEntry(options, Instant.now());
        requestStore.put(username, entry);
    }

    public PublicKeyCredentialCreationOptions getRequest(String username) {
        // Clean up expired entries before retrieving
        cleanupExpiredEntries();
        
        RequestEntry entry = requestStore.get(username);
        return (entry != null) ? entry.options() : null;
    }

    private void cleanupExpiredEntries() {
        Instant cutoff = Instant.now().minusSeconds(TIMEOUT_SECONDS);
        requestStore.entrySet().removeIf(entry -> entry.getValue().timestamp().isBefore(cutoff));
    }

    public record RequestEntry(PublicKeyCredentialCreationOptions options, Instant timestamp) {
    }
}