package models

import (
	"time"
)

type Result struct {
	ScanResponse
	Status           string         `json:"status"`
	ScannedAt        time.Time      `json:"scanned_at"`
	Server           Info           `json:"server"`
	DetectedServices []string       `json:"detected_services"`
	TotalDomains     int            `json:"total_domains"`
	Domains          []DomainResult `json:"domains"`
	Warnings         []string       `json:"warnings,omitempty"`
	ErrorEvents      []ScanError    `json:"-"`
}

type DomainResult struct {
	Domain
	DNS DNSResult `json:"dns"`
}

type ScanError struct {
	Type      string    `json:"type"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Component string    `json:"component,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}
