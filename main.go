package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

type ComposerLock struct {
	Packages    []Package `json:"packages"`
	PackagesDev []Package `json:"packages-dev"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type OSVQuery struct {
	Queries []OSVSingleQuery `json:"queries"`
}

type OSVSingleQuery struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type OSVResponse struct {
	Results []OSVResult `json:"results"`
}

type OSVResult struct {
	Vulns []OSVVuln `json:"vulns"`
}

type OSVVuln struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Severity   []OSVSeverity  `json:"severity"`
	References []OSVReference `json:"references"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type AffectedEntry struct {
	Severity []OSVSeverity `json:"severity"`
}

type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

type VulnDetail struct {
	ID               string           `json:"id"`
	Aliases          []string         `json:"aliases"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Severity         []OSVSeverity    `json:"severity"`
	References       []OSVReference   `json:"references"`
	Affected         []AffectedEntry  `json:"affected"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

var (
	rootCmd = &cobra.Command{
		Use:   "laravel-vuln-scan",
		Short: "A Laravel/Composer vulnerability + exploit scanner. This checks if any packages in your composer.lock are listed in the OSV database.",
		Run:   runScan,
	}

	path      string
	jsonOut   bool
	ignoreDev bool
	verbose   bool
	checkPocs bool
	osvScan   bool
)

func init() {
	rootCmd.Flags().StringVarP(&path, "path", "p", ".", "Path to Laravel project root")
	rootCmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON instead of table")
	rootCmd.Flags().BoolVar(&ignoreDev, "ignore-dev", false, "Ignore dev packages")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose mode (full details)")
	rootCmd.Flags().BoolVar(&checkPocs, "pocs", false, "Aggressively hunt & highlight potential PoCs")
	rootCmd.Flags().BoolVar(&osvScan, "osv", true, "Use OSV.dev (recommended)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	lockPath := filepath.Join(path, "composer.lock")
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		color.Red("x composer.lock not found at %s", lockPath)
		os.Exit(1)
	}

	data, err := os.ReadFile(lockPath)
	if err != nil {
		color.Red("x Failed to read composer.lock: %v", err)
		os.Exit(1)
	}

	var lock ComposerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		color.Red("x Failed to parse composer.lock: %v", err)
		os.Exit(1)
	}

	// Build package list
	pkgMap := make(map[string]Package)
	pkgs := lock.Packages
	if !ignoreDev {
		pkgs = append(pkgs, lock.PackagesDev...)
	}
	for _, p := range pkgs {
		key := p.Name + "@" + p.Version
		pkgMap[key] = p
	}

	color.Green("Found %d packages", len(pkgMap))

	if !osvScan {
		color.Yellow("OSV scan disabled — nothing to check")
		os.Exit(0)
	}

	// Build OSV batch query - hardened for Packagist naming
	queries := make([]OSVSingleQuery, 0, len(pkgMap))
	for _, p := range pkgMap {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		queries = append(queries, OSVSingleQuery{
			Package: OSVPackage{
				Ecosystem: "Packagist",
				Name:      name,
			},
			Version: p.Version,
		})
	}

	// Hit OSV
	reqBody, _ := json.Marshal(OSVQuery{Queries: queries})
	req, _ := http.NewRequest("POST", "https://api.osv.dev/v1/querybatch", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		color.Red("x OSV API failed: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		color.Red("x Failed to decode OSV response: %v", err)
		os.Exit(1)
	}

	// Process results
	type ScanResult struct {
		Package  string
		Version  string
		Vuln     OSVVuln
		HasPoC   bool
		PoCLinks []string
		Severity string
	}

	var results []ScanResult
	severityCount := make(map[string]int)
	vulnPkgs := make(map[string]bool)
	vulnIDs := []string{}

	for i, result := range osvResp.Results {
		if len(result.Vulns) == 0 {
			continue
		}
		pkg := queries[i]
		vulnPkgs[pkg.Package.Name] = true

		for _, v := range result.Vulns {
			vulnIDs = append(vulnIDs, v.ID)
		}
	}

	vulnDetails := fetchVulnDetails(client, vulnIDs)

	for i, result := range osvResp.Results {
		if len(result.Vulns) == 0 {
			continue
		}
		pkg := queries[i]

		for _, v := range result.Vulns {
			detail := vulnDetails[v.ID]
			sev := getSeverity(detail)
			severityCount[sev]++

			hasPoC := false
			pocLinks := []string{}
			if checkPocs {
				for _, ref := range v.References {
					lower := strings.ToLower(ref.URL)
					if strings.Contains(lower, "poc") || strings.Contains(lower, "exploit") ||
						strings.Contains(lower, "metasploit") || strings.Contains(lower, "proof-of-concept") {
						hasPoC = true
						pocLinks = append(pocLinks, ref.URL)
					}
				}
			}

			results = append(results, ScanResult{
				Package:  pkg.Package.Name,
				Version:  pkg.Version,
				Vuln:     v,
				HasPoC:   hasPoC,
				PoCLinks: pocLinks,
				Severity: sev,
			})
		}
	}

	if jsonOut {
		out := map[string]interface{}{
			"packages_scanned":    len(pkgMap),
			"vulnerable_packages": len(vulnPkgs),
			"total_vulns":         len(results),
			"severity_counts":     severityCount,
			"results":             results,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	// Prepare colored sprint functions for table
	redSprint := color.New(color.FgRed).SprintFunc()
	yellowSprint := color.New(color.FgYellow).SprintFunc()
	greenSprint := color.New(color.FgGreen).SprintFunc()
	whiteSprint := color.New(color.FgWhite).SprintFunc()

	// Pretty colored table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Package", "Version", "Vuln ID", "Severity"})
	if checkPocs {
		table.SetHeader(append([]string{"Package", "Version", "Vuln ID", "Severity"}, "PoC Hunt"))
	}
	table.SetAutoWrapText(false)
	table.SetRowLine(true)
	table.SetBorder(true)
	table.SetCenterSeparator("│")
	table.SetColumnSeparator("│")

	for _, r := range results {
		sevFunc := whiteSprint
		switch r.Severity {
		case "CRITICAL", "HIGH":
			sevFunc = redSprint
		case "MEDIUM":
			sevFunc = yellowSprint
		case "LOW":
			sevFunc = greenSprint
		}

		row := []string{
			r.Package,
			r.Version,
			r.Vuln.ID,
			sevFunc(r.Severity),
			// truncate(r.Vuln.Summary, 70),
		}
		if checkPocs {
			if r.HasPoC {
				pocStr := redSprint("POSSIBLE POC FOUND")
				if verbose {
					pocStr += "\n" + strings.Join(r.PoCLinks, "\n")
				}
				row = append(row, pocStr)
			} else {
				row = append(row, greenSprint("No obvious PoC"))
			}
		}
		table.Append(row)
	}

	table.Render()

	// Summary
	boldWhite := color.New(color.Bold, color.FgWhite)
	boldWhite.Println("\n=== SCAN SUMMARY ===")

	color.Green("Packages scanned: %d", len(pkgMap))
	color.Yellow("Vulnerable packages: %d", len(vulnPkgs))
	color.Red("Total vulnerabilities found: %d", len(results))

	for sev, count := range severityCount {
		switch sev {
		case "CRITICAL", "HIGH":
			color.Red("%s: %d", sev, count)
		case "MEDIUM":
			color.Yellow("%s: %d", sev, count)
		case "LOW":
			color.Green("%s: %d", sev, count)
		default:
			color.White("%s: %d", sev, count)
		}
	}

	if len(results) > 0 {
		color.Red("\nVULNERABLE APPLICATION DETECTED — check the table above!")
		if checkPocs {
			color.Red("PoC hunting enabled — review highlighted references immediately!")
		}
		os.Exit(1)
	}

	color.Green("\nNo known vulnerabilities. Ship it.")
}

func getSeverity(detail VulnDetail) string {
	sevs := detail.Severity
	if len(sevs) == 0 {
		for _, aff := range detail.Affected {
			if len(aff.Severity) > 0 {
				sevs = aff.Severity
				break
			}
		}
	}

	dbSev := detail.DatabaseSpecific.Severity

	if len(sevs) == 0 {
		if dbSev != "" {
			return mapDBSeverity(dbSev)
		}
		return "UNKNOWN"
	}
	scoreStr := sevs[0].Score

	if strings.HasPrefix(scoreStr, "CVSS:") {
		score, ok := getCVSSScore(scoreStr)
		if !ok {
			if dbSev != "" {
				return mapDBSeverity(dbSev)
			}
			return "MEDIUM"
		}
		return mapCVSSScore(score)
	}

	score, err := strconv.ParseFloat(scoreStr, 64)
	if err != nil {
		if dbSev != "" {
			return mapDBSeverity(dbSev)
		}
		return "MEDIUM"
	}
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func getCVSSScore(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "Base Score:") {
			scoreStr := strings.TrimPrefix(part, "Base Score:")
			score, err := strconv.ParseFloat(scoreStr, 64)
			return score, err == nil
		}
	}
	return 0, false
}

func mapCVSSScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func mapDBSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func fetchVulnDetails(client *http.Client, vulnIDs []string) map[string]VulnDetail {
	if len(vulnIDs) == 0 {
		return make(map[string]VulnDetail)
	}

	details := make(map[string]VulnDetail)
	for _, id := range vulnIDs {
		req, _ := http.NewRequest("GET", "https://api.osv.dev/v1/vulns/"+id, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		var detail VulnDetail
		if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
			continue
		}
		details[id] = detail
	}
	return details
}
