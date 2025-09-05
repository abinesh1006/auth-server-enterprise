package com.example.authserver.client;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface ClientRepository extends JpaRepository<ClientEntity, UUID> {
    Optional<ClientEntity> findByClientId(String clientId);
    
    @Query("""
        SELECT DISTINCT c FROM ClientEntity c 
        LEFT JOIN FETCH c.authMethods 
        LEFT JOIN FETCH c.grantTypes 
        LEFT JOIN FETCH c.redirectUris 
        LEFT JOIN FETCH c.scopes 
        WHERE c.id = :id
        """)
    Optional<ClientEntity> findByIdWithRelationships(@Param("id") UUID id);
    
    @Query("""
        SELECT DISTINCT c FROM ClientEntity c 
        LEFT JOIN FETCH c.authMethods 
        LEFT JOIN FETCH c.grantTypes 
        LEFT JOIN FETCH c.redirectUris 
        LEFT JOIN FETCH c.scopes 
        WHERE c.clientId = :clientId
        """)
    Optional<ClientEntity> findByClientIdWithRelationships(@Param("clientId") String clientId);
}