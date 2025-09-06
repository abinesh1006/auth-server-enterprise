package com.example.authserver.security.webauthn;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;

import com.example.authserver.user.UserEntity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class LoginResponse {

	private UUID userId;
	private String username;
	private String firstName;
	private String lastName;
	private String accessToken;
	private String refreshToken;
	private Double ratePerHour;
	private String profileFileURL;
	private boolean enabledMFAForUser;
	private boolean forceMFARegister;
	private List<String> roles;

	public static LoginResponse toDTO(UserEntity user, String accessToken, String refreshToken, String bucketName,
			boolean isMFARegistered) {

		return LoginResponse.builder().userId(user.getId()).accessToken(accessToken).refreshToken(refreshToken)
				.username(user.getUsername()).firstName(user.getFirstName()).lastName(user.getLastName())
				.ratePerHour(user.getRatePerHour())
				.profileFileURL(userProfileLink(user.getProfileFileName(), bucketName))
				.enabledMFAForUser(user.getIsMfaEnabled())
				.forceMFARegister(user.getIsMfaEnabled() && !isMFARegistered ? true : false)
				//.roles(user.getUserRoles())
				.build();
	}

	private static String userProfileLink(String key, String bucket) {
		return StringUtils.isNotEmpty(key)
				? ("https://" + bucket + ".s3.amazonaws.com/" + URLEncoder.encode(key, StandardCharsets.UTF_8))
				: "";
	}
}
