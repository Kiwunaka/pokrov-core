package option

// The host admits one authenticated endpoint/profile and supplies its bounded
// windows. This option does not contain credentials or create access authority.
type PokrovATSLeaseOutboundOptions struct {
	UpstreamTag      string `json:"upstream_tag"`
	LeaseID          string `json:"lease_id"`
	IssuedAt         string `json:"issued_at"`
	NewFlowsUntil    string `json:"new_flows_until"`
	ActiveFlowsUntil string `json:"active_flows_until"`
}
