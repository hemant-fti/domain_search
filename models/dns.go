package models

type InspectOptions struct {
	Domains bool
	Config  bool
	Version bool
}

type DNSResult struct {
	ResolvedIPs   []string `json:"resolved_ips"`
	MatchesServer bool     `json:"matches_server"`
	Status        string   `json:"status"`
}
