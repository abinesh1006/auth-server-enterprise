package com.example.authserver.security.webauthn;


import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Service
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Builder
@Data
public class RegistrationResponse {

	private String deviceCode;

	private LocalDateTime createdAt;

	private String message;

}
