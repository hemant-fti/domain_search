package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"domain-search/cmd/output"
	"domain-search/internal/discovery"
	"domain-search/models"
	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

var errDomainNotFound = errors.New("domain not found")

func NewDomainsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "domains", Short: "Discover configured domains and perform DNS lookups"}
	cmd.AddCommand(NewDomainsCommandForServer("list", ""), NewDomainsGetdatabyServerNameCommand())
	return cmd
}

// NewDomainsCommandForServer lists virtual hosts for one web server,
// or for every registered inspector when serverName is empty.
func NewDomainsCommandForServer(use, serverName string) *cobra.Command {
	return newResultCommand(use, "List configured virtual hosts",
		func(ctx context.Context, cmd *cobra.Command, _ []string) (models.CommandResult, error) {
			start := time.Now()
			svc := discovery.NewLocalService()

			names := []string{serverName}
			if serverName == "" {
				names = svc.InspectorNames()
			}
			if len(names) == 0 {
				return models.CommandResult{}, errors.New("no web server inspectors are registered for this platform")
			}

			logger.Info("Domain inspection started", "servers", names)
			domains, failures := inspectDomains(ctx, svc, names)
			logger.Info("Domain inspection completed",
				"domains_found", len(domains), "failed_servers", len(failures),
				"duration", time.Since(start).String())

			if len(domains) == 0 && len(failures) > 0 {
				return models.CommandResult{}, fmt.Errorf("domain discovery failed: %s", strings.Join(failures, "; "))
			}
			warn(cmd, failures)

			if len(domains) == 0 {
				return result(domains, "No virtual hosts were found."), nil
			}
			var human strings.Builder
			if err := output.WriteDomains(&human, domains); err != nil {
				return models.CommandResult{}, err
			}
			return result(domains, human.String()), nil
		})
}

func NewDomainsGetdatabyServerNameCommand() *cobra.Command {
	return newResultCommand("get-data-by-name <domain>", "Retrieve domain data by name",
		func(ctx context.Context, _ *cobra.Command, args []string) (models.CommandResult, error) {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return models.CommandResult{}, errors.New("domain name cannot be empty")
			}

			start := time.Now()
			logger.Info("Domain lookup started", "domain", name)

			svc := discovery.NewLocalService()
			domains, failures := inspectDomains(ctx, svc, svc.InspectorNames())

			for _, d := range domains {
				if !matchesDomain(d, name) {
					continue
				}
				logger.Info("Domain lookup completed",
					"domain", name, "server", d.Source, "duration", time.Since(start).String())

				var human strings.Builder
				if err := output.WriteDomain(&human, d, failures); err != nil {
					return models.CommandResult{}, err
				}
				return result(d, human.String()), nil
			}

			if len(failures) > 0 {
				return models.CommandResult{}, fmt.Errorf("%w: %q (some servers could not be inspected: %s)",
					errDomainNotFound, name, strings.Join(failures, "; "))
			}
			return models.CommandResult{}, fmt.Errorf("%w: %q in available web server configurations",
				errDomainNotFound, name)
		}, withArgs(cobra.ExactArgs(1)))
}

// inspectDomains collects domains from each named server. One failing server
// never aborts the rest; its error is returned in failures instead.
func inspectDomains(ctx context.Context, svc *discovery.Service, names []string) (domains []models.Domain, failures []string) {
	domains = make([]models.Domain, 0)

	for _, name := range names {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err.Error())
			break
		}

		logger.Debug("Discovering virtual hosts", "server", name)
		res, err := svc.Inspect(ctx, name, models.InspectOptions{Domains: true})
		if err != nil {
			logger.Error(err, "Failed to discover web server domains", "server", name)
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if res.Detected {
			domains = append(domains, res.Domains...)
		}
	}
	return domains, failures
}

// matchesDomain reports a case-insensitive match on name, website name or alias.
func matchesDomain(d models.Domain, name string) bool {
	eq := func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), name) }
	return eq(d.Name) || eq(d.WebsiteName) || slices.ContainsFunc(d.Aliases, eq)
}

// warn prints non-fatal problems to stderr so stdout/JSON stays clean.
func warn(cmd *cobra.Command, failures []string) {
	for _, f := range failures {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", f)
	}
}
