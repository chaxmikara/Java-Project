package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.UpdateUserRequest;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;
import com.codejam.codex.authzen.endpoint.UserEndpoint;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Handles secured endpoints related to authenticated user actions such as
 * viewing/updating profile, refreshing tokens, and logout.
 */
@RestController
@RequestMapping(ApiEndpoint.USER)
// Temporarily removed for testing - @PreAuthorize("hasRole('USER')")
public class UserController {

    private final AuthEndpoint authEndpoint;
    private final UserEndpoint userEndpoint;

    @Autowired
    public UserController(AuthEndpoint authEndpoint, UserEndpoint userEndpoint) {
        this.authEndpoint = authEndpoint;
        this.userEndpoint = userEndpoint;
    }

    /**
     * Retrieves the authenticated user's profile.
     *
     * @param request HttpServletRequest with access token
     * @return User profile in standardized response format
     */
    @GetMapping(ApiEndpoint.AUTH_ME)
    public ResponseEntity<AuthzenResponse<UserResponse>> getProfile(HttpServletRequest request) {
        try {
            if (!authEndpoint.isAuthenticated(request)) {
                AuthzenResponse<UserResponse> response = new AuthzenResponse<>(null, false, "Unauthorized: Invalid or missing token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            String username = authEndpoint.getUsername(request);
            if (username == null) {
                AuthzenResponse<UserResponse> response = new AuthzenResponse<>(null, false, "Unauthorized: Cannot extract username");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            UserResponse profile = userEndpoint.getProfile(username);
            AuthzenResponse<UserResponse> response = new AuthzenResponse<>(profile);
            response.setMessage("User profile retrieved successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("Error in getProfile: " + e.getMessage());
            e.printStackTrace();
            AuthzenResponse<UserResponse> response = new AuthzenResponse<>(null, false, "Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Updates the authenticated user's profile.
     *
     * @param request       HttpServletRequest with access token
     * @param updateRequest Updated user information
     * @return Success message
     */
    @PutMapping(ApiEndpoint.AUTH_UPDATE)
    public ResponseEntity<AuthzenResponse<UpdateUserResponse>> updateProfile(
            HttpServletRequest request,
            @RequestBody UpdateUserRequest updateRequest
    ) {
        try {
            if (!authEndpoint.isAuthenticated(request)) {
                AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(null, false, "Unauthorized: Invalid or missing token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            String username = authEndpoint.getUsername(request);
            if (username == null) {
                AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(null, false, "Unauthorized: Cannot extract username");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            UpdateUserResponse updateUserResponse = userEndpoint.updateUser(username, updateRequest);
            AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(updateUserResponse);
            response.setMessage("User updated successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("Error in updateProfile: " + e.getMessage());
            e.printStackTrace();
            AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(null, false, "Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Logs out the authenticated user.
     * Note: This is a stateless operation unless token blacklisting is implemented.
     *
     * @param request HttpServletRequest with access token
     * @return Success message
     */
    @PostMapping(ApiEndpoint.AUTH_LOGOUT)
    public ResponseEntity<AuthzenResponse<Object>> logout(HttpServletRequest request) {
        try {
            if (!authEndpoint.isAuthenticated(request)) {
                AuthzenResponse<Object> response = new AuthzenResponse<>(null, false, "Unauthorized: Invalid or missing token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            boolean blacklisted = authEndpoint.blacklistToken(request);

            if (blacklisted) {
                AuthzenResponse<Object> response = new AuthzenResponse<>();
                response.setMessage("User logged out successfully");
                return ResponseEntity.ok(response);
            } else {
                AuthzenResponse<Object> response = new AuthzenResponse<>(null, false, "Failed to blacklist token");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
            }
        } catch (Exception e) {
            System.out.println("Error in logout: " + e.getMessage());
            e.printStackTrace();
            AuthzenResponse<Object> response = new AuthzenResponse<>(null, false, "Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}