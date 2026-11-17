package discovery

import (
	"context"
	"time"

	"domain-scout/service/dns"
	"domain-scout/service/inspectors"
	osExec "domain-scout/service/os"
	"domain-scout/service/server"
)

type Service struct {
	inspectors    []inspectors.Inspector
	serverService *server.Service
	verifier      *dns.Verifier
}

func NewService(list []inspectors.Inspector) *Service {
	return &Service{
		inspectors:    list,
		serverService: server.NewService(),
		verifier:      dns.NewVerifier(),
	}
}

func (s *Service) Discover(
	ctx context.Context,
	ex osExec.Executor,
) (Result, error) {

	result := newResult()

	info, err := s.serverService.GetInfo(ctx, ex)
	if err != nil {
		return result, err
	}

	result.Server = info

	var found []inspectors.Domain

	for _, inspector := range s.inspectors {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		// Collect detailed system information when supported.
		if collector, ok := inspector.(systemCollector); ok {
			systemInfo, warnings, collectErr := collector.Collect(ctx, ex)

			result.System = systemInfo
			result.Warnings = append(result.Warnings, warnings...)

			if collectErr != nil {
				if ctx.Err() != nil {
					return result, ctx.Err()
				}

				result.Warnings = append(
					result.Warnings,
					inspector.Name()+" information: "+collectErr.Error(),
				)
			}
		}

		// Detect installed service.
		detected, detectErr := inspector.Detect(ctx, ex)

		if detectErr != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}

			result.Warnings = append(
				result.Warnings,
				inspector.Name()+" detection: "+detectErr.Error(),
			)

			continue
		}

		if !detected {
			continue
		}

		result.DetectedServices = append(
			result.DetectedServices,
			inspector.Name(),
		)

		// System inspector collects information but has no domains.
		if inspector.Name() == "system" {
			continue
		}

		serverInfo, domains, warnings, err := scanInspector(
			ctx,
			inspector,
			ex,
		)

		if err != nil {
			return result, err
		}

		result.Servers = append(result.Servers, serverInfo)
		result.Warnings = append(result.Warnings, warnings...)

		found = append(found, domains...)
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Merge duplicate domains.
	found = Normalize(found)

	// Verify DNS records.
	for _, domain := range found {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		domainResult := DomainResult{
			Domain: domain,
			DNS: s.verifier.Verify(
				ctx,
				domain.Name,
				info.PrimaryIP,
			),
		}

		if err := ctx.Err(); err != nil {
			return result, err
		}

		result.Domains = append(result.Domains, domainResult)
	}

	result.TotalDomains = len(result.Domains)

	return result, nil
}

func newResult() Result {
	return Result{
		ScanResponse: ScanResponse{
			Servers: []ServerInfo{},
			System: SystemInfo{
				IPv4: []string{},
				IPv6: []string{},
			},
		},
		Status:           "completed",
		ScannedAt:        time.Now().UTC(),
		DetectedServices: []string{},
		Domains:          []DomainResult{},
		Warnings:         []string{},
	}
}
