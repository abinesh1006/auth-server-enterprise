package com.example.authserver.api;


import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.authserver.security.WebAuthnService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/webauthn")
@RequiredArgsConstructor
public class WebAuthnController {
	private final Environment environment;
	private final WebAuthnService webAuthService;
	
	@GetMapping(value = "/register")
	public Response getRegistrationOptions(HttpServletRequest request){
		
		if (!UserUtility.isAuthenticated()) {
			return new ErrorResponse(environment.getProperty("user.unauthorized"));
		}
		
		return new SuccessResponse(webAuthService.fetchRegisterOptions(request), "Success", "OK", 200);
	}
	
	@PostMapping("/finishauth")
	public Response finishRegisration(@RequestParam String credential, @RequestParam String deviceCode,
			@RequestParam String deviceName, @RequestParam String location, HttpServletRequest request) {
		
		if (!UserUtility.isAuthenticated()) {
			return new ErrorResponse(environment.getProperty("user.unauthorized"));
		}
		
		return new SuccessResponse(webAuthService.finishRegistartions(credential, deviceCode, deviceName, location, request));
	}
	
	@PostMapping("/initlogin")
	public Response startLogin(@RequestParam String username, HttpServletRequest request) {
		if(!webAuthService.isReadyForLogin(username)) {
			return new ErrorResponse(environment.getProperty("user.mfa.not.registered"));
		}
		
		if(!webAuthService.isMFAEnabled(username)) {
			return new ErrorResponse(environment.getProperty("user.mfa.disabled"));
		}
		
		return new SuccessResponse(webAuthService.initLogin(username, request), "Success", "OK", 200);
	}
	
	@PostMapping("/login")
	public Response finishLogin(@RequestParam String credential, @RequestParam String username, HttpServletRequest request) {
		try{
            return new SuccessResponse(webAuthService.finishLogin(credential, username, request), 200);
        }
        catch(PasswordExpiredException e){
            return new ErrorResponse(environment.getProperty("password.expired"), e.getMessage(), 411);
        }
        catch (UserBlockedException e){
            return new ErrorResponse(e.getMessage(), 412);
        }
        catch (UserDisabledException e){
            return new ErrorResponse(e.getMessage(), 413);
        }
        catch (Exception e){
            return new ErrorResponse(e.getMessage(), 401);
        }
	}
}
