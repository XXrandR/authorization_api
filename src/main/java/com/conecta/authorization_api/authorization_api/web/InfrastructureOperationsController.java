package com.conecta.authorization_api.authorization_api.web;

import com.conecta.authorization_api.authorization_api.service.InfrastructureOperationsService;
import com.conecta.authorization_api.authorization_api.service.AdminQueryService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/infrastructure")
@PreAuthorize("hasAuthority('INFRASTRUCTURE_INTERNAL')")
public class InfrastructureOperationsController {
    private final InfrastructureOperationsService operations;
    private final AdminQueryService queries;

    public InfrastructureOperationsController(InfrastructureOperationsService operations, AdminQueryService queries) {
        this.operations = operations;
        this.queries = queries;
    }

    @GetMapping("/records/{resource}")
    AdminQueryService.Result records(@PathVariable String resource, @RequestParam(defaultValue = "") String q,
                                    @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size) {
        return queries.page(resource, q, page, size);
    }

    @PostMapping("/identities")
    InfrastructureOperationsService.IdentityView createIdentity(@Valid @RequestBody CreateIdentityRequest request) {
        return operations.createIdentity(request.username(), request.email(), request.password(), request.roles());
    }

    @PostMapping("/identities/{id}/revoke-access")
    void revokeIdentityAccess(@PathVariable UUID id) { operations.revokeIdentityAccess(id); }

    @GetMapping("/browser-sessions")
    List<InfrastructureOperationsService.BrowserSessionView> browserSessions() { return operations.browserSessions(); }

    @DeleteMapping("/browser-sessions/{id}")
    void revokeBrowserSession(@PathVariable String id) { operations.revokeBrowserSession(id); }

    @PostMapping("/invitations/{id}/resend")
    void resend(@PathVariable UUID id) { operations.resendInvitation(id); }

    @GetMapping("/identities")
    List<InfrastructureOperationsService.IdentityView> identities() {
        return operations.identities();
    }

    @GetMapping("/roles")
    List<String> roles() {
        return operations.roles();
    }

    @GetMapping("/role-management")
    List<InfrastructureOperationsService.RoleView> roleViews() {
        return operations.roleViews();
    }

    @PostMapping("/roles")
    InfrastructureOperationsService.RoleView createRole(@Valid @RequestBody RoleRequest request) {
        return operations.createRole(request.name());
    }

    @PostMapping("/roles/{id}")
    void renameRole(@PathVariable UUID id, @Valid @RequestBody RoleRequest request) {
        operations.renameRole(id, request.name());
    }

    @DeleteMapping("/roles/{id}")
    void deleteRole(@PathVariable UUID id) {
        operations.deleteRole(id);
    }

    @PostMapping("/identities/{id}/roles")
    void roles(@PathVariable UUID id, @Valid @RequestBody RolesRequest request) {
        operations.replaceRoles(id, request.roles());
    }

    @PostMapping("/identities/{id}/block")
    void block(@PathVariable UUID id, @RequestBody BlockRequest request) {
        operations.block(id, request.blocked());
    }

    @PostMapping("/identities/{id}")
    void updateIdentity(@PathVariable UUID id, @Valid @RequestBody IdentityRequest request) {
        operations.updateIdentityAndRoles(id, request.username(), request.email(), request.active(), request.roles());
    }

    @DeleteMapping("/identities/{id}")
    void deleteIdentity(@PathVariable UUID id) {
        operations.deleteIdentity(id);
    }

    @GetMapping("/invitations")
    List<Map<String, Object>> invitations() {
        return operations.invitations();
    }

    @PostMapping("/invitations")
    void invite(@Valid @RequestBody InvitationRequest request) {
        operations.invite(request.email(), request.roles());
    }

    @PostMapping("/invitations/{id}/revoke")
    void revoke(@PathVariable UUID id) {
        operations.revokeInvitation(id);
    }

    @GetMapping("/sessions")
    List<Map<String, Object>> sessions() {
        return operations.sessions();
    }

    @DeleteMapping("/sessions/{id}")
    void revokeSession(@PathVariable String id) {
        operations.revokeSession(id);
    }

    @GetMapping("/audit-events")
    List<Map<String, Object>> audit() {
        return operations.auditEvents();
    }

    @GetMapping("/access-events")
    List<Map<String, Object>> access() {
        return operations.accessEvents();
    }

    record RolesRequest(@NotEmpty Set<@NotBlank String> roles) {
    }

    record BlockRequest(boolean blocked) {
    }

    record InvitationRequest(@NotBlank @Email String email, @NotEmpty Set<@NotBlank String> roles) {
    }

    record RoleRequest(@NotBlank @Pattern(regexp = "[A-Z][A-Z0-9_]{1,49}") String name) {
    }

    record IdentityRequest(@NotBlank String username, @NotBlank @Email String email, boolean active, @NotEmpty Set<@NotBlank String> roles) {
    }
    record CreateIdentityRequest(@Pattern(regexp = "[a-zA-Z0-9._-]{3,50}") @NotBlank String username,
                                 @NotBlank @Email String email, @Size(min = 12, max = 72) @NotBlank String password,
                                 @NotEmpty Set<@NotBlank String> roles) { }
}
