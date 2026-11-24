package discovery

import (
	"domain-search/models"
	"reflect"
	"testing"
)

func TestNormalizeMergesCertificatePathsAndSortsUniquePorts(t *testing.T) {
	domains := Normalize([]models.Domain{
		{
			Name:           "www.example.com",
			Ports:          []int{443, 80},
			SSLCertificate: "/etc/ssl/example.pem",
		},
		{
			Name:  "www.example.com",
			Ports: []int{8080, 443},
		},
	})

	if len(domains) != 1 {
		t.Fatalf("got %d normalized domains, want 1", len(domains))
	}
	domain := domains[0]
	if domain.SSLCertificate != "/etc/ssl/example.pem" {
		t.Errorf("SSL certificate = %q", domain.SSLCertificate)
	}

	if !reflect.DeepEqual(domain.Ports, []int{80, 443, 8080}) {
		t.Errorf("ports = %#v, want [80 443 8080]", domain.Ports)
	}
}
