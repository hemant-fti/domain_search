package dns

import (
	"context"
	"domain-search/internal/logger"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type RecordResult struct {
	Domain  string   `json:"domain"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
}

func (r *Resolver) LookupRecord(ctx context.Context, record, domain string) (RecordResult, error) {
	startedAt := time.Now()

	record = strings.ToUpper(strings.TrimSpace(record))

	result := RecordResult{
		Domain:  domain,
		Type:    record,
		Records: []string{},
	}

	logger.Debug("DNS record lookup started",
		"domain", domain,
		"record", record,
	)

	var err error

	switch record {
	case "A", "AAAA":
		network := "ip4"
		if record == "AAAA" {
			network = "ip6"
		}

		var addresses []netip.Addr
		addresses, err = r.client.LookupNetIP(ctx, network, domain)
		if err == nil {
			for _, address := range addresses {
				result.Records = append(result.Records, address.String())
			}
		}

	case "MX":
		var records []*net.MX
		records, err = r.client.LookupMX(ctx, domain)
		if err == nil {
			for _, item := range records {
				result.Records = append(result.Records, fmt.Sprintf("%d %s", item.Pref, item.Host))
			}
		}

	case "NS":
		var records []*net.NS
		records, err = r.client.LookupNS(ctx, domain)
		if err == nil {
			for _, item := range records {
				result.Records = append(result.Records, item.Host)
			}
		}

	case "TXT":
		var records []string
		records, err = r.client.LookupTXT(ctx, domain)
		if err == nil {
			result.Records = append(result.Records, records...)
		}

	default:
		err = fmt.Errorf(
			"unsupported DNS record type %q (supported: A, AAAA, MX, NS, TXT)",
			record,
		)
	}

	if err != nil {
		if record == "A" || record == "AAAA" || record == "MX" || record == "NS" || record == "TXT" {
			err = fmt.Errorf("lookup %s records for %s: %w", record, domain, err)
		}

		logger.Debug("DNS record lookup failed",
			"domain", domain,
			"record", record,
			"error", err,
			"duration", time.Since(startedAt).String(),
		)

		return result, err
	}

	sort.Strings(result.Records)

	logger.Debug("DNS record lookup completed",
		"domain", domain,
		"record", record,
		"results", len(result.Records),
		"duration", time.Since(startedAt).String(),
	)

	return result, nil
}
