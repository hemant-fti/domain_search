package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sampleConfig = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <sites>
      <site name="Default Web Site" id="1">
        <application path="/">
          <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" />
        </application>
        <bindings>
          <binding protocol="http" bindingInformation="*:80:" />
          <binding protocol="net.tcp" bindingInformation="808:*" />
        </bindings>
      </site>
      <site name="Shop" id="2">
        <application path="/app"><virtualDirectory path="/" physicalPath="D:\other" /></application>
        <application path="/"><virtualDirectory path="/" physicalPath="D:\sites\shop" /></application>
        <bindings>
          <binding protocol="HTTPS" bindingInformation="*:443:shop.example.com" sslFlags="1" />
          <binding protocol="https" bindingInformation="[2001:db8::1]:8443:" certificateHash="ab cd" certificateStoreName="WebHosting" />
          <binding protocol="http" bindingInformation="10.0.0.5:80:shop.example.com" />
          <binding protocol="http" bindingInformation="*:99999:bad.example.com" />
        </bindings>
      </site>
      <site name="Api" id="3">
        <bindings>
          <binding protocol="https" bindingInformation="*:443:api.example.com" sslFlags="3" />
        </bindings>
      </site>
    </sites>
  </system.applicationHost>
  <system.webServer>
    <rewrite><rules>
      <rule name="global" enabled="true"><action type="Rewrite" url="http://localhost:9000/{R:1}" /></rule>
    </rules></rewrite>
  </system.webServer>
  <location path="Shop">
    <system.webServer><rewrite><rules>
      <rule name="off" enabled="false"><action type="Rewrite" url="http://disabled:1" /></rule>
      <rule name="redirect"><action type="Redirect" url="https://elsewhere" /></rule>
      <rule name="proxy"><action type="Rewrite" url="http://127.0.0.1:5000/{R:1}" /></rule>
    </rules></rewrite></system.webServer>
  </location>
</configuration>`

func TestParse(t *testing.T) {
	sites, err := Parse([]byte(sampleConfig))
	if err == nil || !strings.Contains(err.Error(), `site "Shop", binding "*:99999:bad.example.com"`) {
		t.Fatalf("Parse error = %v, want the invalid port reported", err)
	}
	if len(sites) != 3 {
		t.Fatalf("got %d sites, want 3", len(sites))
	}

	def, shop, api := sites[0], sites[1], sites[2]

	if def.PhysicalPath != `%SystemDrive%\inetpub\wwwroot` {
		t.Errorf("default PhysicalPath = %q", def.PhysicalPath)
	}
	if len(def.Bindings) != 1 || def.Bindings[0] != (Binding{Protocol: "http", IP: "*", Port: 80}) {
		t.Errorf("default bindings = %+v (net.tcp must be skipped)", def.Bindings)
	}
	if def.ProxyTarget != "http://localhost:9000/{R:1}" {
		t.Errorf("default ProxyTarget = %q, want global rule", def.ProxyTarget)
	}

	if shop.ID != "2" || shop.PhysicalPath != `D:\sites\shop` {
		t.Errorf("shop = %+v", shop)
	}
	if shop.ProxyTarget != "http://127.0.0.1:5000/{R:1}" {
		t.Errorf("shop ProxyTarget = %q, want site rule", shop.ProxyTarget)
	}
	wantShop := []Binding{
		{Protocol: "https", IP: "*", Port: 443, Host: "shop.example.com", SSLFlags: SSLFlagSNI},
		{Protocol: "https", IP: "2001:db8::1", Port: 8443, CertificateHash: "ab cd", CertificateStore: "WebHosting"},
		{Protocol: "http", IP: "10.0.0.5", Port: 80, Host: "shop.example.com"},
	}
	if !reflect.DeepEqual(shop.Bindings, wantShop) {
		t.Errorf("shop bindings =\n%+v\nwant\n%+v", shop.Bindings, wantShop)
	}

	if api.Bindings[0].SSLFlags&SSLFlagCCS == 0 {
		t.Errorf("api CCS flag missing: %+v", api.Bindings[0])
	}
}

func TestParseRejectsInvalidXML(t *testing.T) {
	if _, err := Parse([]byte("<configuration><unclosed>")); err == nil {
		t.Fatal("expected XML error")
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applicationHost.config")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	sites, _ := Load(path)
	if len(sites) != 3 {
		t.Fatalf("Load returned %d sites", len(sites))
	}
	if _, err := Load(path + ".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load(missing) error = %v", err)
	}
}

func TestParseBindingInformation(t *testing.T) {
	tests := []struct {
		in       string
		ip       string
		port     int
		host     string
		wantFail bool
	}{
		{in: "*:443:example.com", ip: "*", port: 443, host: "example.com"},
		{in: ":80:", ip: "*", port: 80},
		{in: "192.0.2.1:8080:", ip: "192.0.2.1", port: 8080},
		{in: "[::1]:443:v6.example.com", ip: "::1", port: 443, host: "v6.example.com"},
		{in: " *:443:spaced.example.com ", ip: "*", port: 443, host: "spaced.example.com"},
		{in: "*:0:x", wantFail: true},
		{in: "*:65536:x", wantFail: true},
		{in: "*:abc:x", wantFail: true},
		{in: "*:443", wantFail: true},
		{in: "[::1:443:x", wantFail: true},
		{in: "808:*", wantFail: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ip, port, host, err := ParseBindingInformation(tt.in)
			if tt.wantFail {
				if err == nil {
					t.Fatalf("expected error, got %s %d %s", ip, port, host)
				}
				return
			}
			if err != nil || ip != tt.ip || port != tt.port || host != tt.host {
				t.Fatalf("got (%q, %d, %q, %v), want (%q, %d, %q)", ip, port, host, err, tt.ip, tt.port, tt.host)
			}
		})
	}
}

func TestNormalizeIP(t *testing.T) {
	tests := map[string]string{
		"": "*", "*": "*", "0.0.0.0": "*", "::": "*", "[::]": "*",
		"[2001:DB8::1]": "2001:db8::1", " 10.0.0.1 ": "10.0.0.1",
	}
	for in, want := range tests {
		if got := NormalizeIP(in); got != want {
			t.Errorf("NormalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
	if !IsWildcardIP("0.0.0.0") || IsWildcardIP("10.0.0.1") {
		t.Error("IsWildcardIP misclassified")
	}
}

func TestExpandPath(t *testing.T) {
	env := map[string]string{"SystemDrive": "C:", "windir": `C:\Windows`}
	getenv := func(k string) string { return env[k] }

	tests := map[string]string{
		`%SystemDrive%\inetpub\wwwroot`: `C:\inetpub\wwwroot`,
		`%windir%\temp`:                 `C:\Windows\temp`,
		`%Unknown%\x`:                   `%Unknown%\x`,
		`D:\plain`:                      `D:\plain`,
		`100%`:                          `100%`,
		`%Unknown%%SystemDrive%`:        `%Unknown%C:`,
	}
	for in, want := range tests {
		if got := ExpandPath(in, getenv); got != want {
			t.Errorf("ExpandPath(%q) = %q, want %q", in, got, want)
		}
	}
}
