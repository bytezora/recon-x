package vulns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssAPIURL = "https://api.first.org/data/v1/epss"
)

type EnrichOptions struct {
	NVDAPIKey         string
	Timeout           time.Duration
	MaxPerFingerprint int
}

type EnrichReport struct {
	Enabled             bool     `json:"enabled"`
	Fingerprints        int      `json:"fingerprints"`
	FingerprintsWithCPE int      `json:"fingerprints_with_cpe"`
	NVDQueries          int      `json:"nvd_queries"`
	NVDMatches          int      `json:"nvd_matches"`
	NVDErrors           []string `json:"nvd_errors,omitempty"`
	KEVLoaded           int      `json:"kev_loaded"`
	EPSSLoaded          int      `json:"epss_loaded"`
}

type kevEntry struct {
	CVEID                   string `json:"cveID"`
	VendorProject           string `json:"vendorProject"`
	Product                 string `json:"product"`
	VulnerabilityName       string `json:"vulnerabilityName"`
	DateAdded               string `json:"dateAdded"`
	ShortDescription        string `json:"shortDescription"`
	RequiredAction          string `json:"requiredAction"`
	DueDate                 string `json:"dueDate"`
	KnownRansomwareCampaign string `json:"knownRansomwareCampaignUse"`
	Notes                   string `json:"notes"`
}

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
		CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
		CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
		CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	References struct {
		ReferenceData []struct {
			URL string `json:"url"`
		} `json:"referenceData"`
	} `json:"references"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type epssRecord struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
}

type epssResponse struct {
	Data []epssRecord `json:"data"`
}

func EnrichLive(ctx context.Context, fingerprints []Fingerprint, existing []Match, opts EnrichOptions) ([]Match, error) {
	matches, _, err := EnrichLiveDetailed(ctx, fingerprints, existing, opts)
	return matches, err
}

func EnrichLiveDetailed(ctx context.Context, fingerprints []Fingerprint, existing []Match, opts EnrichOptions) ([]Match, EnrichReport, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxPerFingerprint <= 0 {
		opts.MaxPerFingerprint = 200
	}
	report := EnrichReport{Enabled: true, Fingerprints: len(fingerprints)}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	client := &http.Client{Timeout: opts.Timeout}
	out := append([]Match{}, existing...)
	seen := make(map[string]int)
	for i, m := range out {
		seen[matchKey(m)] = i
	}

	unique := uniqueFingerprints(fingerprints)
	for _, fp := range unique {
		if fp.CPE == "" {
			continue
		}
		report.FingerprintsWithCPE++
		report.NVDQueries++
		matches, err := queryNVD(ctx, client, fp, opts)
		if err != nil {
			report.NVDErrors = append(report.NVDErrors, fp.CPE+": "+err.Error())
			continue
		}
		report.NVDMatches += len(matches)
		for _, m := range matches {
			key := matchKey(m)
			if idx, ok := seen[key]; ok {
				out[idx] = mergeMatch(out[idx], m)
				continue
			}
			seen[key] = len(out)
			out = append(out, m)
		}
	}

	kev, _ := fetchKEV(ctx, client)
	report.KEVLoaded = len(kev)
	applyKEV(out, kev)
	epss, _ := fetchEPSS(ctx, client, out)
	report.EPSSLoaded = len(epss)
	applyEPSS(out, epss)
	for i := range out {
		out[i].Priority = priorityFor(out[i])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return matchSortScore(out[i]) > matchSortScore(out[j])
	})
	return out, report, nil
}

func uniqueFingerprints(in []Fingerprint) []Fingerprint {
	seen := make(map[string]bool)
	var out []Fingerprint
	for _, fp := range in {
		key := fp.Host + "|" + strconv.Itoa(fp.Port) + "|" + fp.CPE
		if fp.CPE == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fp)
	}
	return out
}

func queryNVD(ctx context.Context, client *http.Client, fp Fingerprint, opts EnrichOptions) ([]Match, error) {
	cpe := normalizeCPE23(fp.CPE)
	if cpe == "" {
		return nil, fmt.Errorf("empty cpe")
	}
	pageSize := opts.MaxPerFingerprint
	if pageSize <= 0 || pageSize > 2000 {
		pageSize = 2000
	}
	maxResults := opts.MaxPerFingerprint
	if maxResults <= 0 {
		maxResults = 200
	}
	var matches []Match
	for start := 0; start < maxResults; start += pageSize {
		page, err := queryNVDPage(ctx, client, fp, cpe, opts, start, pageSize)
		if err != nil {
			return matches, err
		}
		matches = append(matches, page.matches...)
		if len(page.matches) == 0 || page.total == 0 || start+page.pageSize >= page.total || len(matches) >= maxResults {
			break
		}
	}
	if len(matches) > maxResults {
		matches = matches[:maxResults]
	}
	return matches, nil
}

type nvdPage struct {
	matches  []Match
	total    int
	pageSize int
}

func queryNVDPage(ctx context.Context, client *http.Client, fp Fingerprint, cpe string, opts EnrichOptions, start, pageSize int) (nvdPage, error) {
	values := url.Values{}
	values.Set("virtualMatchString", cpe)
	values.Set("resultsPerPage", strconv.Itoa(pageSize))
	values.Set("startIndex", strconv.Itoa(start))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdAPIBase+"?"+values.Encode(), nil)
	if err != nil {
		return nvdPage{}, err
	}
	req.Header.Set("User-Agent", "recon-x CVE enrichment")
	if opts.NVDAPIKey != "" {
		req.Header.Set("apiKey", opts.NVDAPIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nvdPage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nvdPage{}, fmt.Errorf("nvd status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nvdPage{}, err
	}
	var parsed nvdResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nvdPage{}, err
	}

	matches := make([]Match, 0, len(parsed.Vulnerabilities))
	for _, item := range parsed.Vulnerabilities {
		m := matchFromNVD(fp, item.CVE)
		if m.CVE != "" {
			matches = append(matches, m)
		}
	}
	return nvdPage{matches: matches, total: parsed.TotalResults, pageSize: parsed.ResultsPerPage}, nil
}

func normalizeCPE23(cpe string) string {
	cpe = strings.TrimSpace(cpe)
	if cpe == "" || strings.HasPrefix(cpe, "cpe:2.3:") {
		return cpe
	}
	if !strings.HasPrefix(cpe, "cpe:/") {
		return cpe
	}
	raw := strings.TrimPrefix(cpe, "cpe:/")
	parts := strings.Split(raw, ":")
	if len(parts) < 3 {
		return cpe
	}
	for len(parts) < 11 {
		parts = append(parts, "*")
	}
	return "cpe:2.3:" + strings.Join(parts[:11], ":")
}

func matchFromNVD(fp Fingerprint, c nvdCVE) Match {
	score, sev := nvdScore(c)
	desc := nvdDescription(c)
	link := nvdBase + c.ID
	if len(c.References.ReferenceData) > 0 && c.References.ReferenceData[0].URL != "" {
		link = c.References.ReferenceData[0].URL
	}
	confidence := "medium"
	if fp.Version != "" {
		confidence = "high"
	}
	return Match{
		Host:        fp.Host,
		Port:        fp.Port,
		Banner:      fp.Evidence,
		Product:     fp.Product,
		Version:     fp.Version,
		CPE:         fp.CPE,
		CVE:         c.ID,
		CVSS:        score,
		Severity:    sev,
		Description: desc,
		Link:        link,
		Confidence:  confidence,
		Source:      "nvd-live",
	}
}

func nvdScore(c nvdCVE) (float64, string) {
	metricSets := [][]nvdMetric{
		c.Metrics.CVSSMetricV40,
		c.Metrics.CVSSMetricV31,
		c.Metrics.CVSSMetricV30,
		c.Metrics.CVSSMetricV2,
	}
	for _, set := range metricSets {
		if len(set) == 0 {
			continue
		}
		m := set[0]
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		if sev == "" {
			sev = severityFromScore(m.CVSSData.BaseScore)
		}
		return m.CVSSData.BaseScore, strings.ToUpper(sev)
	}
	return 0, "UNKNOWN"
}

func nvdDescription(c nvdCVE) string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" && d.Value != "" {
			return d.Value
		}
	}
	if len(c.Descriptions) > 0 {
		return c.Descriptions[0].Value
	}
	return "NVD CVE match"
}

func severityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func fetchKEV(ctx context.Context, client *http.Client) (map[string]kevEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cisaKEVURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kev status %d", resp.StatusCode)
	}
	var parsed struct {
		Vulnerabilities []kevEntry `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	out := make(map[string]kevEntry, len(parsed.Vulnerabilities))
	for _, item := range parsed.Vulnerabilities {
		out[item.CVEID] = item
	}
	return out, nil
}

func applyKEV(matches []Match, kev map[string]kevEntry) {
	for i := range matches {
		item, ok := kev[matches[i].CVE]
		if !ok {
			continue
		}
		matches[i].KEV = true
		matches[i].KEVDueDate = item.DueDate
		if matches[i].Description == "" {
			matches[i].Description = item.VulnerabilityName
		}
	}
}

func fetchEPSS(ctx context.Context, client *http.Client, matches []Match) (map[string]epssRecord, error) {
	cves := uniqueCVEs(matches)
	out := make(map[string]epssRecord)
	for start := 0; start < len(cves); start += 100 {
		end := start + 100
		if end > len(cves) {
			end = len(cves)
		}
		values := url.Values{}
		values.Set("cve", strings.Join(cves[start:end], ","))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssAPIURL+"?"+values.Encode(), nil)
		if err != nil {
			return out, err
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var parsed epssResponse
		err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&parsed)
		resp.Body.Close()
		if err != nil {
			continue
		}
		for _, row := range parsed.Data {
			out[row.CVE] = row
		}
	}
	return out, nil
}

func uniqueCVEs(matches []Match) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		if m.CVE == "" || seen[m.CVE] {
			continue
		}
		seen[m.CVE] = true
		out = append(out, m.CVE)
	}
	sort.Strings(out)
	return out
}

func applyEPSS(matches []Match, epss map[string]epssRecord) {
	for i := range matches {
		row, ok := epss[matches[i].CVE]
		if !ok {
			continue
		}
		matches[i].EPSS, _ = strconv.ParseFloat(row.EPSS, 64)
		matches[i].EPSSPercent, _ = strconv.ParseFloat(row.Percentile, 64)
	}
}

func mergeMatch(old, fresh Match) Match {
	if fresh.Source != "" && !strings.Contains(old.Source, fresh.Source) {
		if old.Source == "" {
			old.Source = fresh.Source
		} else {
			old.Source += "," + fresh.Source
		}
	}
	if fresh.CVSS > old.CVSS {
		old.CVSS = fresh.CVSS
		old.Severity = fresh.Severity
	}
	if old.Description == "" {
		old.Description = fresh.Description
	}
	if old.Link == "" {
		old.Link = fresh.Link
	}
	if old.Product == "" {
		old.Product = fresh.Product
	}
	if old.Version == "" {
		old.Version = fresh.Version
	}
	if old.CPE == "" {
		old.CPE = fresh.CPE
	}
	if confidenceWeight(fresh.Confidence) > confidenceWeight(old.Confidence) {
		old.Confidence = fresh.Confidence
	}
	return old
}

func DedupeMatches(in []Match) []Match {
	seen := make(map[string]int)
	out := make([]Match, 0, len(in))
	for _, m := range in {
		key := matchKey(m)
		if idx, ok := seen[key]; ok {
			out[idx] = mergeMatch(out[idx], m)
			continue
		}
		seen[key] = len(out)
		out = append(out, m)
	}
	for i := range out {
		out[i].Priority = priorityFor(out[i])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return matchSortScore(out[i]) > matchSortScore(out[j])
	})
	return out
}

func matchKey(m Match) string {
	return m.Host + "|" + strconv.Itoa(m.Port) + "|" + m.CVE
}

func confidenceWeight(c string) int {
	switch strings.ToLower(c) {
	case "confirmed":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func priorityFor(m Match) string {
	score := matchSortScore(m)
	switch {
	case score >= 115:
		return "P0"
	case score >= 90:
		return "P1"
	case score >= 60:
		return "P2"
	default:
		return "P3"
	}
}

func matchSortScore(m Match) float64 {
	score := m.CVSS * 10
	if m.KEV {
		score += 35
	}
	score += m.EPSS * 25
	if m.Confidence == "confirmed" {
		score += 25
	} else if m.Confidence == "high" {
		score += 10
	}
	return score
}
