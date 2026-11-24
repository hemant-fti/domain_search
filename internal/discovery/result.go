package discovery

import (
	"domain-search/internal/dns"
	"domain-search/internal/server"
	"domain-search/models"
	"time"
)

type Result struct {
	ScanResponse
	Status           string         `json:"status"`
	ScannedAt        time.Time      `json:"scanned_at"`
	Server           server.Info    `json:"server"`
	DetectedServices []string       `json:"detected_services"`
	TotalDomains     int            `json:"total_domains"`
	Domains          []DomainResult `json:"domains"`
	Warnings         []string       `json:"warnings,omitempty"`
	ErrorEvents      []ScanError    `json:"-"`
}

type DomainResult struct {
	models.Domain
	DNS dns.Result `json:"dns"`
}

type SystemInfo = server.SystemInfo

type DiskInfo = server.DiskInfo

type MemoryInfo = server.MemoryInfo
