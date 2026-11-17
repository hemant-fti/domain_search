package dns

import "context"

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
		status := "unresolved"

		if ctx.Err() != nil {
			status = "unresolved"
		}

		return Result{
			ResolvedIPs:   []string{},
			MatchesServer: false,
			Status:        status,
		}
	}

	if len(ips) == 0 {
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

	return Result{
		ResolvedIPs:   ips,
		MatchesServer: matches,
		Status:        status,
	}
}
