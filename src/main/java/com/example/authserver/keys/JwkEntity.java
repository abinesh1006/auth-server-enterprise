package com.example.authserver.keys;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name="jwk_keys")
@Getter @Setter
public class JwkEntity {
    @Id @GeneratedValue
    private UUID id;

    @Column(unique = true, nullable = false) 
    private String kid;
    
    // Relational columns instead of JSONB
    @Column(name="key_type", nullable = false) 
    private String kty; // RSA, EC, etc.
    
    @Column(name="algorithm", nullable = false) 
    private String alg; // RS256, ES256, etc.
    
    @Column(name="key_use", nullable = false) 
    private String use; // sig, enc
    
    @Column(name="key_ops") 
    private String keyOps; // verify, sign, etc.
    
    // RSA specific fields
    @Column(name="modulus", columnDefinition = "TEXT") 
    private String n; // RSA modulus
    
    @Column(name="exponent") 
    private String e; // RSA exponent
    
    @Column(name="private_exponent", columnDefinition = "TEXT") 
    private String d; // RSA private exponent
    
    @Column(name="first_prime_factor", columnDefinition = "TEXT") 
    private String p; // RSA first prime factor
    
    @Column(name="second_prime_factor", columnDefinition = "TEXT") 
    private String q; // RSA second prime factor
    
    @Column(name="first_crt_exponent", columnDefinition = "TEXT") 
    private String dp; // RSA first CRT exponent
    
    @Column(name="second_crt_exponent", columnDefinition = "TEXT") 
    private String dq; // RSA second CRT exponent
    
    @Column(name="crt_coefficient", columnDefinition = "TEXT") 
    private String qi; // RSA CRT coefficient
    
    // EC specific fields
    @Column(name="curve") 
    private String crv; // P-256, P-384, P-521
    
    @Column(name="x_coordinate", columnDefinition = "TEXT") 
    private String x; // EC x coordinate
    
    @Column(name="y_coordinate", columnDefinition = "TEXT") 
    private String y; // EC y coordinate
    
    @Column(name="ecc_private_key", columnDefinition = "TEXT") 
    private String ecPrivateKey; // EC private key
    
    // Certificate chain
    @Column(name="certificate_chain", columnDefinition = "TEXT") 
    private String x5c; // Certificate chain
    
    @Column(name="certificate_thumbprint") 
    private String x5t; // Certificate thumbprint
    
    @Column(name="certificate_thumbprint_s256") 
    private String x5tS256; // Certificate thumbprint SHA-256
    
    @Column(name="certificate_url") 
    private String x5u; // Certificate URL
    
    @Column(name="use_for", nullable = false) 
    private String useFor;
    
    private Boolean active = Boolean.TRUE;
}