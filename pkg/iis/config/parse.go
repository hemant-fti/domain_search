// Package config reads IIS's applicationHost.config.
//
// It is pure parsing with no Windows API calls, so it builds and is tested on
// every platform. It is the only place that parses IIS bindingInformation.
package config

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// IIS sslFlags bits.
const (
	SSLFlagSNI uint32 = 1 // Server Name Indication
	SSLFlagCCS uint32 = 2 // Centralized Certificate Store
)

// Site is one IIS website.
type Site struct {
	ID       string
	Name     string
	Bindings []Binding
	// PhysicalPath is the root application's root virtual directory, with
	// %VARIABLES% left unexpanded (see ExpandPath).
	PhysicalPath string
	// ProxyTarget is the first enabled URL Rewrite rule that rewrites to an
	// http(s) URL: site-specific <location> rules first, then global rules.
	ProxyTarget string
}

// Binding is one site binding, e.g. https *:443:example.com.
type Binding struct {
	Protocol string // lower case: http, https, net.tcp, ...
	IP       string // "*" means all unassigned addresses; IPv6 without brackets
	Port     int
	Host     string // empty when the binding has no host name
	SSLFlags uint32
	// CertificateHash and CertificateStore are only present in the config
	// for some bindings; HTTP.sys is the source of truth.
	CertificateHash  string
	CertificateStore string
}

// HTTPS reports whether the binding is an HTTPS binding.
func (b Binding) HTTPS() bool { return b.Protocol == "https" }

// Path returns the location of applicationHost.config, or an error if it
// does not exist (IIS not installed, or no permission).
func Path() (string, error) {
	windowsDir := os.Getenv("windir")
	if windowsDir == "" {
		windowsDir = `C:\Windows`
	}
	build := func(systemDir string) string {
		return filepath.Join(windowsDir, systemDir, "inetsrv", "config", "applicationHost.config")
	}

	// A 32-bit process on 64-bit Windows is redirected away from System32.
	// Sysnative bypasses that, but does not exist on native 32-bit Windows.
	if runtime.GOARCH == "386" {
		if p := build("Sysnative"); fileExists(p) {
			return p, nil
		}
	}

	p := build("System32")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("IIS configuration unavailable at %s: %w", p, err)
	}
	return p, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Load reads and parses the configuration file at path.
func Load(path string) ([]Site, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read IIS configuration %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses applicationHost.config content.
//
// Malformed http/https bindings do not stop parsing: the valid sites are
// returned together with an error describing every skipped binding. Bindings
// of other protocols (net.tcp, net.pipe, ...) use different formats and are
// skipped silently when they do not look like ip:port:host.
func Parse(data []byte) ([]Site, error) {
	var cfg xmlConfiguration
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse IIS configuration: %w", err)
	}

	var sites []Site
	var errs []error

	for _, s := range cfg.SystemApplicationHost.Sites.Sites {
		site := Site{
			ID:           s.ID,
			Name:         s.Name,
			PhysicalPath: rootPhysicalPath(s),
			ProxyTarget:  proxyTarget(cfg, s.Name),
		}

		for _, b := range s.Bindings {
			protocol := strings.ToLower(strings.TrimSpace(b.Protocol))
			if protocol == "" {
				continue
			}
			ip, port, host, err := ParseBindingInformation(b.BindingInformation)
			if err != nil {
				if protocol == "http" || protocol == "https" {
					errs = append(errs, fmt.Errorf("site %q, binding %q: %w", s.Name, b.BindingInformation, err))
				}
				continue
			}
			var flags uint64
			if v := strings.TrimSpace(b.SSLFlags); v != "" {
				// An unparseable value is treated as 0 so the binding is still inspected.
				flags, _ = strconv.ParseUint(v, 10, 32)
			}
			site.Bindings = append(site.Bindings, Binding{
				Protocol:         protocol,
				IP:               ip,
				Port:             port,
				Host:             host,
				SSLFlags:         uint32(flags),
				CertificateHash:  strings.TrimSpace(b.CertificateHash),
				CertificateStore: strings.TrimSpace(b.CertificateStoreName),
			})
		}
		sites = append(sites, site)
	}
	return sites, errors.Join(errs...)
}

var errBindingFormat = errors.New("expected <ip>:<port>:<host>")

// ParseBindingInformation splits an IIS bindingInformation value
// "<ip>:<port>:<host>". IPv6 addresses are bracketed ("[::1]:443:host") and
// returned without brackets. An empty IP is returned as "*".
func ParseBindingInformation(info string) (ip string, port int, host string, err error) {
	info = strings.TrimSpace(info)

	var rest string
	if strings.HasPrefix(info, "[") {
		end := strings.Index(info, "]")
		if end < 0 || end+1 >= len(info) || info[end+1] != ':' {
			return "", 0, "", errBindingFormat
		}
		ip, rest = info[1:end], info[end+2:]
	} else {
		var ok bool
		ip, rest, ok = strings.Cut(info, ":")
		if !ok {
			return "", 0, "", errBindingFormat
		}
	}

	portText, host, ok := strings.Cut(rest, ":")
	if !ok {
		return "", 0, "", errBindingFormat
	}
	port, err = strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", fmt.Errorf("invalid port %q", portText)
	}

	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "*"
	}
	return ip, port, strings.TrimSpace(host), nil
}

// IsWildcardIP reports whether ip means "all unassigned addresses".
func IsWildcardIP(ip string) bool {
	return NormalizeIP(ip) == "*"
}

// NormalizeIP makes binding IPs from different sources comparable:
// "", "*", "0.0.0.0", "::" and "[::]" become "*"; brackets are removed and
// the result is lower case.
func NormalizeIP(ip string) string {
	ip = strings.ToLower(strings.TrimSpace(ip))
	ip = strings.TrimSuffix(strings.TrimPrefix(ip, "["), "]")
	switch ip {
	case "", "*", "0.0.0.0", "::":
		return "*"
	}
	return ip
}

// ExpandPath replaces %NAME% references in an IIS path using getenv.
// Unknown variables are left as they are. A nil getenv uses os.Getenv.
func ExpandPath(value string, getenv func(string) string) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	var b strings.Builder
	for {
		start := strings.IndexByte(value, '%')
		if start < 0 {
			break
		}
		end := strings.IndexByte(value[start+1:], '%')
		if end < 0 {
			break
		}
		end += start + 1
		name := value[start+1 : end]
		if v := getenv(name); name != "" && v != "" {
			b.WriteString(value[:start])
			b.WriteString(v)
		} else {
			b.WriteString(value[:end])
			value = value[end:]
			continue
		}
		value = value[end+1:]
	}
	b.WriteString(value)
	return b.String()
}

func rootPhysicalPath(site xmlSite) string {
	for _, app := range site.Applications {
		if app.Path != "/" {
			continue
		}
		for _, dir := range app.VirtualDirectories {
			if dir.Path == "/" {
				return strings.TrimSpace(dir.PhysicalPath)
			}
		}
	}
	return ""
}

func proxyTarget(cfg xmlConfiguration, siteName string) string {
	for _, location := range cfg.Locations {
		if !strings.EqualFold(location.Path, siteName) {
			continue
		}
		if target := firstProxyRule(location.WebServer.Rewrite); target != "" {
			return target
		}
	}
	return firstProxyRule(cfg.SystemWebServer.Rewrite)
}

func firstProxyRule(rewrite xmlRewrite) string {
	for _, rule := range rewrite.Rules {
		if strings.EqualFold(rule.Enabled, "false") || !strings.EqualFold(rule.Action.Type, "Rewrite") {
			continue
		}
		target := strings.TrimSpace(rule.Action.URL)
		lower := strings.ToLower(target)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			return target
		}
	}
	return ""
}
