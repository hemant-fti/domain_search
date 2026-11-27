package iis

import (
	"reflect"
	"testing"

	"domain-search/pkg/iis/config"
	"domain-search/pkg/models"
)

func TestBuildDomains(t *testing.T) {
	sites := []config.Site{
		{
			ID: "2", Name: "Shop", PhysicalPath: `%SystemDrive%\shop`, ProxyTarget: "http://127.0.0.1:5000",
			Bindings: []config.Binding{
				{Protocol: "https", IP: "*", Port: 443, Host: "shop.example.com"},
				{Protocol: "https", IP: "*", Port: 443, Host: "shop.example.com"}, // duplicate
				{Protocol: "http", IP: "*", Port: 80, Host: "www.shop.example.com"},
				{Protocol: "http", IP: "192.0.2.7", Port: 80, Host: "SHOP.example.com"},
			},
		},
		{
			ID: "3", Name: "Legacy",
			Bindings: []config.Binding{
				{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "", CertificateHash: "aa bb"},
			},
		},
		{ID: "4", Name: "NoBindings"},
	}

	shopCert := models.CertificateResult{Installed: true, FQDN: "shop.example.com", FingerprintSHA1: "SHOPTHUMB", Port: 443}
	legacyCert := models.CertificateResult{Installed: false, Port: 443, Error: "not bound"}

	domains := buildDomains(siteInput{
		configPath: `C:\cfg`,
		sites:      sites,
		statuses:   map[string]string{"Shop": "Started"},
		certs: map[bindingKey]models.CertificateResult{
			{ip: "*", port: 443, host: "shop.example.com"}: shopCert,
			{ip: "*", port: 443, host: ""}:                 legacyCert,
		},
		localIPs: []string{"192.0.2.7", "2001:db8::7"},
		getenv:   func(k string) string { return map[string]string{"SystemDrive": "C:"}[k] },
	})

	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2 (site without bindings skipped)", len(domains))
	}
	shop, legacy := domains[0], domains[1]

	if shop.Name != "shop.example.com" || shop.Hostname != shop.Name || shop.WebsiteName != "Shop" || shop.ID != "2" {
		t.Errorf("shop identity = %+v", shop)
	}
	if !reflect.DeepEqual(shop.Aliases, []string{"www.shop.example.com"}) {
		t.Errorf("shop aliases = %v (host names compare case-insensitively)", shop.Aliases)
	}
	if !reflect.DeepEqual(shop.Ports, []int{443, 80}) {
		t.Errorf("shop ports = %v", shop.Ports)
	}
	if len(shop.Bindings) != 3 {
		t.Errorf("shop bindings = %d, want 3 after de-duplication", len(shop.Bindings))
	}
	if !reflect.DeepEqual(shop.Bindings[0].ResolvedIPs, []string{"192.0.2.7", "2001:db8::7"}) {
		t.Errorf("wildcard ResolvedIPs = %v", shop.Bindings[0].ResolvedIPs)
	}
	if !reflect.DeepEqual(shop.Bindings[2].ResolvedIPs, []string{"192.0.2.7"}) {
		t.Errorf("explicit ResolvedIPs = %v", shop.Bindings[2].ResolvedIPs)
	}
	if shop.Path != `C:\shop` || shop.Status != "Started" || shop.Source != "iis" || shop.ConfigPath != `C:\cfg` {
		t.Errorf("shop details = %+v", shop)
	}
	if len(shop.Certificates) != 1 || shop.Certificates[0].FingerprintSHA1 != "SHOPTHUMB" {
		t.Errorf("shop certificates = %+v", shop.Certificates)
	}
	if shop.SSLCertificate != "SHOPTHUMB" {
		t.Errorf("shop SSLCertificate = %q, want HTTP.sys thumbprint", shop.SSLCertificate)
	}

	if legacy.Name != "" || legacy.Status != "Unknown" {
		t.Errorf("legacy = %+v", legacy)
	}
	if legacy.SSLCertificate != "AABB" {
		t.Errorf("legacy SSLCertificate = %q, want normalized config hash", legacy.SSLCertificate)
	}
	if len(legacy.Certificates) != 1 || legacy.Certificates[0].Installed {
		t.Errorf("legacy certificates = %+v", legacy.Certificates)
	}
}

func TestHTTPSEndpointsDeduplicatesAcrossSites(t *testing.T) {
	sites := []config.Site{
		{Name: "a", Bindings: []config.Binding{
			{Protocol: "https", IP: "*", Port: 443, Host: "x.test"},
			{Protocol: "http", IP: "*", Port: 80},
		}},
		{Name: "b", Bindings: []config.Binding{
			{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "X.test."},
			{Protocol: "https", IP: "::1", Port: 443},
		}},
	}
	order, byKey := httpsEndpoints(sites)
	if len(order) != 2 {
		t.Fatalf("endpoints = %v, want 2", order)
	}
	if byKey[order[0]].site != "a" {
		t.Errorf("first declaration should win, got site %q", byKey[order[0]].site)
	}
}
