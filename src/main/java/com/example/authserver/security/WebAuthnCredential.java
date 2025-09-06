package com.example.authserver.security;


import java.time.LocalDateTime;

import com.example.authserver.user.UserEntity;
import com.yubico.webauthn.data.ByteArray;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "tb_webauthn_credentials")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class WebAuthnCredential {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "ID")
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "USER_NAME")
	private UserEntity user; // Relationship with User

	@Column(name = "CREDENTIAL_ID", nullable = false)
	private ByteArray credentialId;

	@Column(name = "PUBLIC_KEY_COSE",nullable = false)
	private ByteArray publicKeyCose;

	@Column(name = "SIGNATURE_COUNT", nullable = false)
	private long signatureCount;

	@Column(name = "DISCOVERABLE")
	private Boolean discoverable;

	@Column(name = "AAGUID", nullable = false)
	private ByteArray aaguid;

	@Column(name = "ATTESTATION_OBJECT", nullable = false)
	private ByteArray attestationObject;

	@Column(name = "CLIENT_DATA_JSON", nullable = false)
	private ByteArray clientDataJSON;

	@Column(name = "CREATED_AT", nullable = false, updatable = false)
	@Default
	private LocalDateTime createdAt = LocalDateTime.now();

	@Column(name = "LOCATION", length = 255)
	private String location;

	@Column(name = "USER_AGENT", length = 512)
	private String userAgent;

	@Column(name = "DEVICE_CODE", length = 512)
	private String deviceCode;
}
