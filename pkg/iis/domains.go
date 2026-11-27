package iis

import (
	"fmt"
	"net/netip"
	"strings"

	"domain-search/pkg/iis/config"
	"domain-search/pkg/models"
	"domain-search/pkg/ssl/certificate"
)

// bindingKey identifies one HTTPS endpoint: IP + port + host name.
// Identical endpoints on different sites resolve to the same HTTP.sys entry.
type bindingKey struct {
	ip   string
	port int
	host string
}

func keyOf(b config.Binding) bindingKey {
	return bindingKey{
		ip:   config.NormalizeIP(b.IP),
		port: b.Port,
		host: strings.TrimSuffix(strings.ToLower(b.Host), "."),
	}
}

// siteInput is everything buildDomains needs; collecting it touches Windows
// APIs, building from it does not.
type siteInput struct {
	configPath string
	sites      []config.Site
	statuses   map[string]string                       // site name -> state
	certs      map[bindingKey]models.CertificateResult // HTTPS endpoint -> certificate
	localIPs   []string                                // used for wildcard bindings
	getenv     func(string) string
}

// buildDomains turns IIS sites into domain records, one per website.
func buildDomains(in siteInput) []models.Domain {
	var domains []models.Domain

	for _, site := range in.sites {
		var (
			bindings    []models.Binding
			hosts       []string
			ports       []int
			certs       []models.CertificateResult
			sslHash     string
			seenBinding = map[string]bool{}
			seenHost    = map[string]bool{}
			seenPort    = map[int]bool{}
			seenCert    = map[bindingKey]bool{}
		)

		for _, b := range site.Bindings {
			id := fmt.Sprintf("%s|%s|%d|%s", b.Protocol, b.IP, b.Port, strings.ToLower(b.Host))
			if !seenBinding[id] {
				seenBinding[id] = true
				bindings = append(bindings, models.Binding{
					Protocol:    b.Protocol,
					IP:          b.IP,
					Port:        b.Port,
					Hostname:    b.Host,
					ResolvedIPs: resolvedIPs(b.IP, in.localIPs),
				})
			}

			if b.Host != "" && b.Host != "*" && !seenHost[strings.ToLower(b.Host)] {
				seenHost[strings.ToLower(b.Host)] = true
				hosts = append(hosts, b.Host)
			}
			if !seenPort[b.Port] {
				seenPort[b.Port] = true
				ports = append(ports, b.Port)
			}

			if !b.HTTPS() {
				continue
			}
			if b.CertificateHash != "" {
				sslHash = certificate.NormalizeThumbprint(b.CertificateHash)
			}
			k := keyOf(b)
			if cert, ok := in.certs[k]; ok && !seenCert[k] {
				seenCert[k] = true
				certs = append(certs, cert)
			}
		}

		if len(bindings) == 0 {
			continue // websites without a valid binding are not reachable
		}

		// HTTP.sys is the source of truth when the config has no hash.
		if sslHash == "" {
			for _, c := range certs {
				if c.Installed && c.FingerprintSHA1 != "" {
					sslHash = c.FingerprintSHA1
					break
				}
			}
		}

		status := in.statuses[site.Name]
		if status == "" {
			status = "Unknown"
		}

		var name string
		var aliases []string
		if len(hosts) > 0 {
			name = hosts[0]
			aliases = append(aliases, hosts[1:]...)
		}

		domains = append(domains, models.Domain{
			ID:             site.ID,
			Name:           name,
			WebsiteName:    site.Name,
			Status:         status,
			Bindings:       bindings,
			Path:           config.ExpandPath(site.PhysicalPath, in.getenv),
			Hostname:       name,
			Source:         "iis",
			ConfigPath:     in.configPath,
			ProxyTarget:    site.ProxyTarget,
			SSLCertificate: sslHash,
			Aliases:        aliases,
			Ports:          ports,
			Certificates:   certs,
		})
	}
	return domains
}

// resolvedIPs lists the addresses a binding listens on: every local address
// for a wildcard binding, otherwise the binding's own address.
func resolvedIPs(ip string, local []string) []string {
	if config.IsWildcardIP(ip) {
		return append([]string(nil), local...)
	}
	if addr, err := netip.ParseAddr(ip); err == nil {
		return []string{addr.Unmap().String()}
	}
	return nil
}

// httpsEndpoints returns each distinct HTTPS endpoint across all sites, with
// the first binding that declared it.
func httpsEndpoints(sites []config.Site) ([]bindingKey, map[bindingKey]endpoint) {
	var order []bindingKey
	byKey := map[bindingKey]endpoint{}
	for _, site := range sites {
		for _, b := range site.Bindings {
			if !b.HTTPS() {
				continue
			}
			k := keyOf(b)
			if _, ok := byKey[k]; ok {
				continue
			}
			order = append(order, k)
			byKey[k] = endpoint{site: site.Name, binding: b}
		}
	}
	return order, byKey
}

type endpoint struct {
	site    string
	binding config.Binding
}

// notInstalled is the record for an endpoint whose certificate could not be read.
func notInstalled(b config.Binding, err error) models.CertificateResult {
	r := models.CertificateResult{IP: b.IP, FQDN: b.Host, Port: b.Port, SANs: []string{}}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}
