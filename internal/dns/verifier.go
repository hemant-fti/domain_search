package dns

import (
	"context"
	"domain-search/pkg/logger"
)

type Verifier struct {
	resolver *Resolver
}

func NewVerifier() *Verifier {
	return &Verifier{
		resolver: NewResolver(),
	}
}

func (v *Verifier) Verify(
	ctx context.Context,
	domain string,
	serverIP string,
) Result {
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
