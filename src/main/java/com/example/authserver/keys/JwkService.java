package com.example.authserver.keys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;

@Service
public class JwkService implements JWKSource<SecurityContext> {
    
    private static final Logger logger = LoggerFactory.getLogger(JwkService.class);
    private final JwkRepository repo;
    
    // In-memory cache for JWK keys
    private volatile JWKSet cachedJwkSet;
    private volatile long lastCacheTime = 0;
    private static final long CACHE_TTL = 300_000; // 5 minutes cache TTL
    
    public JwkService(JwkRepository repo) { 
        this.repo = repo; 
    }

    @Transactional
    public void ensureKey() {
        if (repo.findByActiveTrue().isEmpty()) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); 
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                RSAKey rsa = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                        .privateKey((RSAPrivateKey) kp.getPrivate())
                        .keyID(UUID.randomUUID().toString())
                        .build();
                
                // Convert RSAKey to relational entity
                JwkEntity entity = new JwkEntity();
                entity.setKid(rsa.getKeyID());
                entity.setKty("RSA");
                entity.setAlg("RS256");
                entity.setUse("sig");
                entity.setUseFor("sig");
                entity.setActive(true);
                
                // Set RSA components
                entity.setN(rsa.getModulus().toString());
                entity.setE(rsa.getPublicExponent().toString());
                entity.setD(rsa.getPrivateExponent().toString());
                entity.setP(rsa.getFirstPrimeFactor().toString());
                entity.setQ(rsa.getSecondPrimeFactor().toString());
                entity.setDp(rsa.getFirstFactorCRTExponent().toString());
                entity.setDq(rsa.getSecondFactorCRTExponent().toString());
                entity.setQi(rsa.getFirstCRTCoefficient().toString());
                
                repo.save(entity);
            } catch (Exception e) { 
                throw new IllegalStateException("Failed to generate RSA key", e); 
            }
        }
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
        JWKSet jwkSet = getCachedJwkSet();
        return jwkSelector.select(jwkSet);
    }
    
    private JWKSet getCachedJwkSet() {
        long currentTime = System.currentTimeMillis();
        
        // Check if cache is valid
        if (cachedJwkSet != null && (currentTime - lastCacheTime) < CACHE_TTL) {
            logger.debug("Returning cached JWK set");
            return cachedJwkSet;
        }
        
        // Cache miss or expired - reload from database
        synchronized (this) {
            // Double-check locking
            if (cachedJwkSet != null && (currentTime - lastCacheTime) < CACHE_TTL) {
                return cachedJwkSet;
            }
            
            logger.debug("Loading JWK keys from database");
            List<JwkEntity> activeKeys = repo.findByActiveTrue();
            List<JWK> jwks = activeKeys.stream().map(this::convertToJwk).toList();
            
            cachedJwkSet = new JWKSet(jwks);
            lastCacheTime = currentTime;
            
            logger.info("JWK cache refreshed with {} keys", jwks.size());
            return cachedJwkSet;
        }
    }
    
    // Method to clear cache when keys are updated
    public void clearCache() {
        synchronized (this) {
            cachedJwkSet = null;
            lastCacheTime = 0;
            logger.info("JWK cache cleared");
        }
    }
    
    private JWK convertToJwk(JwkEntity entity) {
        try {
            if ("RSA".equals(entity.getKty())) {
                RSAKey.Builder builder = new RSAKey.Builder(
                    new Base64URL(entity.getN()),
                    new Base64URL(entity.getE())
                )
                .keyID(entity.getKid())
                .algorithm(com.nimbusds.jose.Algorithm.parse(entity.getAlg()))
                .keyUse(com.nimbusds.jose.jwk.KeyUse.parse(entity.getUse()));
                
                // Add private key components if available
                if (entity.getD() != null) {
                    builder = builder
                        .privateExponent(new Base64URL(entity.getD()))
                        .firstPrimeFactor(new Base64URL(entity.getP()))
                        .secondPrimeFactor(new Base64URL(entity.getQ()))
                        .firstFactorCRTExponent(new Base64URL(entity.getDp()))
                        .secondFactorCRTExponent(new Base64URL(entity.getDq()))
                        .firstCRTCoefficient(new Base64URL(entity.getQi()));
                }
                
                return builder.build();
            }
            
            throw new IllegalArgumentException("Unsupported key type: " + entity.getKty());
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert entity to JWK", e);
        }
    }
}