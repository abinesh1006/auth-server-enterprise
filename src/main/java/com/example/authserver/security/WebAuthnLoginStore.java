package com.example.authserver.security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.yubico.webauthn.AssertionRequest;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class WebAuthnLoginStore {

	private static final long TIMEOUT_SECONDS = 300; // 5 minutes
	private Map<String, LoginRequestEntry> loginRequestStore = new ConcurrentHashMap<>();

	public void storeRequest(String username, AssertionRequest options) {
		// Clean up expired entries before adding new one
		cleanupExpiredEntries();
		
		LoginRequestEntry entry = new LoginRequestEntry(options, Instant.now());
		loginRequestStore.put(username, entry);
	}

	public AssertionRequest getRequest(String username) {
		// Clean up expired entries before retrieving
		cleanupExpiredEntries();
		
		LoginRequestEntry entry = loginRequestStore.get(username);
		return (entry != null) ? entry.options() : null;
	}

	private void cleanupExpiredEntries() {
		Instant cutoff = Instant.now().minusSeconds(TIMEOUT_SECONDS);
		loginRequestStore.entrySet().removeIf(entry -> entry.getValue().timestamp().isBefore(cutoff));
	}

	public record LoginRequestEntry(AssertionRequest options, Instant timestamp) {
	}
}