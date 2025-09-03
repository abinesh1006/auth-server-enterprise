package com.example.authserver.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController 
@RequestMapping("/api/examples")
@Tag(name = "OAuth2 Examples", description = "Example endpoints showing how to use different OAuth2 grant flows")
public class OAuth2ExamplesController {

    @PostMapping(value = "/password-grant", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(
        summary = "Password Grant Flow Example", 
        description = """
            This endpoint demonstrates the OAuth2 Password Grant flow (Resource Owner Password Credentials).
            
            **Note**: This is just a documentation endpoint - the actual token endpoint is `/oauth2/token`
            
            **How to use:**
            1. Make a POST request to `/oauth2/token` (not this endpoint)
            2. Include client credentials in Authorization header or request body
            3. Send username/password in request body
            4. Optionally include MFA code if MFA is enabled for the tenant
            
            **Bootstrap Client Credentials:**
            - Client ID: `bootstrap-client`
            - Client Secret: `bootstrap-secret`
            """,
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Password grant request parameters",
            content = @Content(
                mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                examples = {
                    @ExampleObject(
                        name = "Basic Password Grant",
                        description = "Basic password grant without MFA",
                        value = """
                        grant_type=password&username=admin@example.com&password=admin123&scope=read write&client_id=bootstrap-client&client_secret=bootstrap-secret
                        """
                    ),
                    @ExampleObject(
                        name = "Password Grant with MFA",
                        description = "Password grant with MFA code",
                        value = """
                        grant_type=password&username=admin@example.com&password=admin123&mfa_code=123456&scope=read write&client_id=bootstrap-client&client_secret=bootstrap-secret
                        """
                    ),
                    @ExampleObject(
                        name = "Using Authorization Header",
                        description = "Client credentials in Authorization header (recommended)",
                        value = """
                        grant_type=password&username=admin@example.com&password=admin123&scope=read write
                        
                        Authorization: Basic Ym9vdHN0cmFwLWNsaWVudDpib290c3RyYXAtc2VjcmV0
                        """
                    )
                }
            )
        ),
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Token issued successfully",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    examples = @ExampleObject(
                        name = "Successful Response",
                        value = """
                        {
                          "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                          "token_type": "Bearer",
                          "expires_in": 3600,
                          "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                          "scope": "read write"
                        }
                        """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "400",
                description = "Bad Request - Invalid parameters",
                content = @Content(
                    examples = @ExampleObject(
                        value = """
                        {
                          "error": "invalid_request",
                          "error_description": "Missing required parameter: username"
                        }
                        """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized - Invalid credentials or MFA required",
                content = @Content(
                    examples = {
                        @ExampleObject(
                            name = "Invalid Credentials",
                            value = """
                            {
                              "error": "invalid_grant",
                              "error_description": "Bad credentials"
                            }
                            """
                        ),
                        @ExampleObject(
                            name = "MFA Required",
                            value = """
                            {
                              "error": "mfa_required",
                              "error_description": "MFA required or invalid"
                            }
                            """
                        )
                    }
                )
            )
        }
    )
    public Map<String, Object> passwordGrantExample(
        @Parameter(description = "Must be 'password'", example = "password")
        @RequestParam("grant_type") String grantType,
        
        @Parameter(description = "User's username/email", example = "admin@example.com")
        @RequestParam String username,
        
        @Parameter(description = "User's password", example = "admin123")
        @RequestParam String password,
        
        @Parameter(description = "Requested scopes (space-separated)", example = "read write")
        @RequestParam(required = false) String scope,
        
        @Parameter(description = "MFA code (if MFA is enabled)", example = "123456")
        @RequestParam(value = "mfa_code", required = false) String mfaCode,
        
        @Parameter(description = "Client ID (if not using Authorization header)", example = "bootstrap-client")
        @RequestParam(value = "client_id", required = false) String clientId,
        
        @Parameter(description = "Client Secret (if not using Authorization header)", example = "bootstrap-secret")
        @RequestParam(value = "client_secret", required = false) String clientSecret
    ) {
        return Map.of(
            "message", "This is a documentation endpoint only!",
            "actual_endpoint", "/oauth2/token",
            "method", "POST",
            "content_type", "application/x-www-form-urlencoded",
            "note", "Use the actual /oauth2/token endpoint for real token requests"
        );
    }

    @GetMapping("/curl-examples")
    @Operation(
        summary = "cURL Examples for OAuth2 Flows",
        description = "Provides ready-to-use cURL commands for testing OAuth2 flows"
    )
    public Map<String, Object> getCurlExamples() {
        return Map.of(
            "password_grant", Map.of(
                "description", "OAuth2 Password Grant Flow",
                "curl_command", """
                    curl -X POST http://localhost:8081/oauth2/token \\
                      -H "Content-Type: application/x-www-form-urlencoded" \\
                      -H "Authorization: Basic Ym9vdHN0cmFwLWNsaWVudDpib290c3RyYXAtc2VjcmV0" \\
                      -d "grant_type=password&username=admin@example.com&password=admin123&scope=read write"
                    """,
                "explanation", "Replace username/password with actual user credentials"
            ),
            "client_credentials", Map.of(
                "description", "OAuth2 Client Credentials Grant Flow",
                "curl_command", """
                    curl -X POST http://localhost:8081/oauth2/token \\
                      -H "Content-Type: application/x-www-form-urlencoded" \\
                      -H "Authorization: Basic Ym9vdHN0cmFwLWNsaWVudDpib290c3RyYXAtc2VjcmV0" \\
                      -d "grant_type=client_credentials&scope=read write"
                    """
            ),
            "authorization_header_explanation", Map.of(
                "base64_encoded", "Ym9vdHN0cmFwLWNsaWVudDpib290c3RyYXAtc2VjcmV0",
                "decoded", "bootstrap-client:bootstrap-secret",
                "note", "This is Base64 encoding of 'client_id:client_secret'"
            ),
            "test_protected_endpoint", Map.of(
                "description", "Use the access token to call protected endpoints",
                "curl_command", """
                    curl -X GET http://localhost:8081/api/admin/tenants \\
                      -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
                    """
            )
        );
    }
}