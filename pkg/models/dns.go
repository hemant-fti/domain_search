package models

// DNSResult is the outcome of checking whether a domain resolves to this server.
type DNSResult struct {
	ResolvedIPs   []string `json:"resolved_ips"`
	MatchesServer bool     `json:"matches_server"`
	Status        string   `json:"status"`
}

// DNS verification statuses.
const (
	DNSStatusMatchesServer   = "matches_server"
	DNSStatusResolvedOtherIP = "resolved_other_ip"
	DNSStatusUnresolved      = "unresolved"
	DNSStatusInvalidServerIP = "invalid_server_ip"
)
