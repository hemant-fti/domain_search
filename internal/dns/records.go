package dns

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type RecordResult struct {
	Domain  string   `json:"domain"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
}

func (r *Resolver) LookupRecord(ctx context.Context, record, domain string) (RecordResult, error) {
	record = strings.ToUpper(strings.TrimSpace(record))
	result := RecordResult{
		Domain:  domain,
		Type:    record,
		Records: []string{},
	}

	switch record {
	case "A", "AAAA":
		network := "ip4"
		if record == "AAAA" {
			network = "ip6"
		}
		addresses, err := r.client.LookupNetIP(ctx, network, domain)
		if err != nil {
			return result, fmt.Errorf("lookup %s record for %s: %w", record, domain, err)
		}
		for _, address := range addresses {
			result.Records = append(result.Records, address.String())
		}
	case "MX":
		records, err := r.client.LookupMX(ctx, domain)
		if err != nil {
			return result, fmt.Errorf("lookup MX records for %s: %w", domain, err)
		}
		for _, item := range records {
			result.Records = append(result.Records, fmt.Sprintf("%d %s", item.Pref, item.Host))
		}
	case "NS":
		records, err := r.client.LookupNS(ctx, domain)
		if err != nil {
			return result, fmt.Errorf("lookup NS records for %s: %w", domain, err)
		}
		for _, item := range records {
			result.Records = append(result.Records, item.Host)
		}
	case "TXT":
		records, err := r.client.LookupTXT(ctx, domain)
		if err != nil {
			return result, fmt.Errorf("lookup TXT records for %s: %w", domain, err)
		}
		result.Records = append(result.Records, records...)
	default:
		return result, fmt.Errorf("unsupported DNS record type %q (supported: A, AAAA, MX, NS, TXT)", record)
	}

	sort.Strings(result.Records)
	return result, nil
}
