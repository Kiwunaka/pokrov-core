package option

// PokrovCatalogWindow binds a top-level domain route/DNS rule to the lifetime
// of the signed catalog from which the application compiled it. It is not a
// signature, entitlement, or provider lease verifier.
type PokrovCatalogWindow struct {
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	ServiceID string `json:"service_id,omitempty"`
	// Only Smart Access rules carry this exact lease identity. Ordinary catalog
	// windows remain independent of the provider path.
	LeaseID string `json:"lease_id,omitempty"`
	LeaseGroup []string `json:"lease_group,omitempty"`
}
