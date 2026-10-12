package com.conecta.authorization_api.authorization_api.web;

import com.conecta.authorization_api.authorization_api.service.InfrastructureClientService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.NotNull;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/infrastructure/clients")
@PreAuthorize("hasAuthority('INFRASTRUCTURE_INTERNAL')")
public class InfrastructureController {
    private final InfrastructureClientService clientService;

    public InfrastructureController(InfrastructureClientService clientService) { this.clientService = clientService; }

    @GetMapping
    List<InfrastructureClientService.ClientSummary> list() { 
		log.info("Listing the clients.");
		return clientService.list(); 
	}

    @PostMapping
    InfrastructureClientService.ClientCredential create(@Valid @RequestBody ClientRequest request) {
        return clientService.create(spec(request));
    }

    @GetMapping("/page")
    InfrastructureClientService.ClientPage page(@RequestParam(defaultValue = "") String q, @RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "20") int size) { return clientService.page(q, page, size); }

    @GetMapping("/{clientId}")
    InfrastructureClientService.ClientDetail detail(@PathVariable String clientId) { return clientService.detail(clientId); }

    @PostMapping("/{clientId}")
    void update(@PathVariable String clientId, @Valid @RequestBody ClientRequest request) { clientService.update(clientId, spec(request), request.enabled()); }

    @PostMapping("/{clientId}/revoke-access")
    void revoke(@PathVariable String clientId) { clientService.revoke(clientId); }

    private InfrastructureClientService.ClientSpec spec(ClientRequest request) {
        return new InfrastructureClientService.ClientSpec(request.clientId(), request.clientName(), request.publicClient(), request.redirectUris(), request.scopes(), request.machine());
    }

    @PostMapping("/{clientId}/secret-rotations")
    InfrastructureClientService.ClientCredential rotate(@PathVariable String clientId) { return clientService.rotateSecret(clientId); }

    @DeleteMapping("/{clientId}")
    void delete(@PathVariable String clientId) { clientService.delete(clientId); }


    record ClientRequest(
            @NotBlank @Pattern(regexp = "^[a-zA-Z0-9._-]{3,100}$") String clientId,
            @NotBlank @Size(max = 255) String clientName,
            boolean publicClient,
            @NotNull @Size(max = 20) List<@NotBlank String> redirectUris,
            @NotNull @Size(min = 1, max = 20) List<@NotBlank String> scopes,
            boolean machine, boolean enabled) {}
}
