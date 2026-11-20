package dns

import (
	"context"
	"domain-search/internal/logger"
	"net/netip"
)

type Verifier struct {
	resolver *Resolver
}

func NewVerifier() *Verifier {
	return &Verifier{
		resolver: NewResolver(),
	}
}

type Result struct {
	ResolvedIPs   []string `json:"resolved_ips"`
	MatchesServer bool     `json:"matches_server"`
	Status        string   `json:"status"`
}

func (v *Verifier) Verify(ctx context.Context, domain string, serverIP string) Result {
	ips, err := v.resolver.LookupIP(ctx, domain)

	if err != nil {
		logger.Warn(
			"DNS lookup failed",
			"domain", domain,
			"error", err,
		)

		return Result{
			ResolvedIPs:   []string{},
			MatchesServer: false,
			Status:        "unresolved",
		}
	}

	if len(ips) == 0 {
		logger.Warn(
			"No IP addresses resolved",
			"domain", domain,
		)

		return Result{
			ResolvedIPs:   []string{},
			MatchesServer: false,
			Status:        "unresolved",
		}
	}

	// Normalize the server IP before comparison.
	serverAddr, err := netip.ParseAddr(serverIP)
	if err != nil {
		logger.Warn(
			"Invalid server IP address",
			"domain", domain,
			"server_ip", serverIP,
			"error", err,
		)

		return Result{
			ResolvedIPs:   ips,
			MatchesServer: false,
			Status:        "invalid_server_ip",
		}
	}

	serverIP = serverAddr.Unmap().String()

	matches := matchesServerIP(ips, serverIP)

	status := "resolved_other_ip"
	if matches {
		status = "matches_server"
	}

	logger.Info(
		"DNS verification completed",
		"domain", domain,
		"server_ip", serverIP,
		"resolved_ips", ips,
		"matches_server", matches,
		"status", status,
	)

	return Result{
		ResolvedIPs:   ips,
		MatchesServer: matches,
		Status:        status,
	}
}
