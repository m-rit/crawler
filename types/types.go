package types

type ScanResponse struct {
	scanResults []ScanResult
}

type ScanResultWrapper struct {
	ScanResult ScanResult `json:"scanResults"`
}
type ScanResult struct {
	ScanID          string          `json:"scan_id"`
	Timestamp       string          `json:"timestamp"`
	ScanStatus      string          `json:"scan_status"`
	ResourceType    string          `json:"resource_type"`
	ResourceName    string          `json:"resource_name"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         Summary         `json:"summary"`
	Metadata        ScanMetadata    `json:"scan_metadata"`
}

type ScanMetadata struct {
	ScannerVersion  string   `json:"scanner_version"`
	PoliciesVersion string   `json:"policies_version"`
	ScanningRules   []string `json:"scanning_rules"`
	ExcludedPaths   []string `json:"excluded_paths"`
}

type Vulnerability struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss"`
	Status         string   `json:"status"`
	PackageName    string   `json:"package_name"`
	CurrentVersion string   `json:"current_version"`
	FixedVersion   string   `json:"fixed_version"`
	Description    string   `json:"description"`
	PublishedDate  string   `json:"published_date"`
	Link           string   `json:"link"`
	RiskFactors    []string `json:"risk_factors"`
}

type Summary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	SeverityCounts       map[string]int `json:"severity_counts"`
	FixableCount         int            `json:"fixable_count"`
	Compliant            bool           `json:"compliant"`
}
