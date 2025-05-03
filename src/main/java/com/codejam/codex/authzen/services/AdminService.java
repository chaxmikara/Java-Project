package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.DelegateRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleUpdateRequest;
import com.codejam.codex.authzen.dtos.outputs.AuditLogResponse;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.AuditLog;
import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.models.UserRole;
import com.codejam.codex.authzen.repositories.AuditLogRepository;
import com.codejam.codex.authzen.repositories.RoleRepository;
import com.codejam.codex.authzen.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditLogRepository auditLogRepository;

    public List<UserResponse> getAllUsers(String adminUsername) {
        logAction(adminUsername, "User list got successfully");

        return userRepository.findAll()
                .stream()
                .map(user -> {
                    // Get user permissions from repository
                    List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
                    // Use the actual user entity from the database
                    return UserResponse.fromEntity(user, permissionNames);
                })
                .toList();
    }

    @Transactional
    public UpdateUserResponse updateUserRoles(Long userId, RoleUpdateRequest request, String adminUsername) {
        try {
            // Find the user using the actual userId parameter
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
            
            // Log for debugging - print the requested role name
            System.out.println("Attempting to assign role: " + request.getRoleName() + " to user: " + user.getUsername());
            
            // Find the role using the roleName from the request
            List<Role> roles = roleRepository.findByName(request.getRoleName());
            if (roles.isEmpty()) {
                throw new RuntimeException("Role not found with name: " + request.getRoleName());
            }
            
            // Clear existing user roles to avoid duplicates
            user.getUserRoles().clear();
            
            // Add the new role to the user
            Role role = roles.get(0);
            UserRole userRole = new UserRole();
            userRole.setUser(user);  // Use the actual user from the database
            userRole.setRole(role);  // Use the actual role from the database
            user.getUserRoles().add(userRole);
            
            // Save the user with the updated roles
            User savedUser = userRepository.save(user);
            
            // Log the action
            logAction(adminUsername, "Updated roles for user: " + user.getUsername() + " to " + request.getRoleName());
            
            return UpdateUserResponse.fromEntity(savedUser);
        } catch (Exception e) {
            System.out.println("Error updating user roles: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to update user roles: " + e.getMessage(), e);
        }
    }

    public List<AuditLogResponse> getAuditLogs(String adminUsername) {
        try {
            // Log that we're fetching audit logs
            System.out.println("Fetching audit logs for admin: " + adminUsername);
            
            // Get all audit logs from the repository
            List<AuditLog> auditLogs = auditLogRepository.findAll();
            
            // Convert to response DTOs
            return auditLogs.stream()
                .map(log -> AuditLogResponse.builder()
                    .id(log.getId())
                    .username(log.getUser() != null ? log.getUser().getUsername() : "unknown")
                    .actionType(log.getActionType())
                    .ipAddress(log.getIpAddress())
                    .timestamp(log.getTimestamp())
                    .build())
                .toList();
        } catch (Exception e) {
            System.out.println("Error retrieving audit logs: " + e.getMessage());
            e.printStackTrace();
            return new ArrayList<>(); // Return empty list on error instead of throwing exception
        }
    }

    @Transactional
    public String delegatePermissions(DelegateRequest request, String adminUsername) {
        try {
            // Find the target user by ID from the request
            User user = userRepository.findById(request.getUserId())
                    .orElseThrow(() -> new RuntimeException("Target user not found with ID: " + request.getUserId()));

            // Find the role to delegate
            List<Role> roles = roleRepository.findByName(request.getRole());
            if (roles.isEmpty()) {
                throw new RuntimeException("Role not found: " + request.getRole());
            }
            Role role = roles.get(0);

            // Check if user already has this role
            boolean alreadyAssigned = user.getUserRoles().stream()
                    .map(userRole -> userRole.getRole().getName())
                    .anyMatch(roleName -> roleName.equals(role.getName()));
            
            if (alreadyAssigned) {
                return "User already has this role";
            }

            // Create and set up the new UserRole relationship
            UserRole userRole = new UserRole();
            userRole.setUser(user);  // Use actual user
            userRole.setRole(role);  // Use actual role
            user.getUserRoles().add(userRole);
            
            // Save the updated user
            userRepository.save(user);
            
            logAction(adminUsername, "Permissions delegated successfully to user ID: " + user.getId());

            return "Permissions delegated successfully";
        } catch (Exception e) {
            System.out.println("Error delegating permissions: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to delegate permissions: " + e.getMessage(), e);
        }
    }

    public String createRole(RoleRequest request, String adminUsername) {
        try {
            // Check if role name already exists
            if (roleRepository.existsByName(request.getRoleName())) {
                throw new IllegalArgumentException("Role already exists with name: " + request.getRoleName());
            }

            // Create new role with data from the request
            Role role = new Role();
            role.setName(request.getRoleName());
            role.setDescription(request.getDescription());

            // Save the properly populated role object
            roleRepository.save(role);

            logAction(adminUsername, "Role created successfully: " + request.getRoleName());

            return "Role created successfully";
        } catch (Exception e) {
            throw new RuntimeException("Failed to create role: " + e.getMessage(), e);
        }
    }

    private void logAction(String adminUsername, String actionType) {
        User adminUser = userRepository.findByUsername(adminUsername)
                .orElseThrow(() -> new RuntimeException("Admin user not found"));

        AuditLog log = new AuditLog();
        log.setUser(adminUser); // Use the fetched admin user entity instead of creating a new one
        log.setActionType(actionType);
        log.setTimestamp(new Timestamp(System.currentTimeMillis()));
        log.setIpAddress("127.0.0.1"); // Default IP address

        auditLogRepository.save(log);
    }

    public UserResponse getUserById(Long userId) {
        // Log for debugging
        System.out.println("Looking up user with ID: " + userId);
        
        // Use the actual userId parameter instead of hardcoded 1L
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        
        // Get user permissions
        List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
        
        // Create and return response with actual user data and permissions
        return UserResponse.fromEntity(user, permissionNames);
    }

}
