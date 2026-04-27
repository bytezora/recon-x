package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bytezora/recon-x/internal/cors"
	"github.com/bytezora/recon-x/internal/defaultcreds"
	"github.com/bytezora/recon-x/internal/sqli"
	"github.com/bytezora/recon-x/internal/takeover"
	"github.com/bytezora/recon-x/internal/templates"
	"github.com/bytezora/recon-x/internal/vulns"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtLoc `json:"artifactLocation"`
}

type sarifArtLoc struct {
	URI string `json:"uri"`
}

func WriteSARIF(path string, cveMatches []vulns.Match, sqliRes []sqli.Result, takeoverRes []takeover.Result, corsRes []cors.Result, credsRes []defaultcreds.Result, tplMatches []templates.Match) error {
	rules := []sarifRule{
		{ID: "CVE", Name: "CVE Match", ShortDescription: sarifMessage{Text: "Known CVE matched via banner/header"}},
		{ID: "SQLI001", Name: "SQLi Detected", ShortDescription: sarifMessage{Text: "SQL injection error string in response"}},
		{ID: "TAKEOVER001", Name: "Subdomain Takeover", ShortDescription: sarifMessage{Text: "Dangling CNAME pointing to unclaimed service"}},
		{ID: "CORS001", Name: "CORS Misconfiguration", ShortDescription: sarifMessage{Text: "Origin reflection or wildcard with credentials"}},
		{ID: "CREDS001", Name: "Default Credentials", ShortDescription: sarifMessage{Text: "Default credentials accepted by login endpoint"}},
		{ID: "TEMPLATE001", Name: "Template Match", ShortDescription: sarifMessage{Text: "Custom or built-in template matched"}},
	}

	var results []sarifResult

	for _, v := range cveMatches {
		level := "warning"
		if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
			level = "error"
		}
		results = append(results, sarifResult{
			RuleID:    v.CVE,
			Level:     level,
			Message:   sarifMessage{Text: fmt.Sprintf("%s on %s:%d — %s", v.CVE, v.Host, v.Port, v.Description)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysLoc{ArtifactLocation: sarifArtLoc{URI: fmt.Sprintf("https://%s", v.Host)}}}},
		})
	}
	for _, s := range sqliRes {
		if s.Detected {
			results = append(results, sarifResult{
				RuleID:    "SQLI001",
				Level:     "error",
				Message:   sarifMessage{Text: fmt.Sprintf("SQLi in param '%s' at %s — evidence: %s", s.Param, s.URL, s.Evidence)},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysLoc{ArtifactLocation: sarifArtLoc{URI: s.URL}}}},
			})
		}
	}
	for _, t := range takeoverRes {
		if t.Vulnerable {
			results = append(results, sarifResult{
				RuleID:    "TAKEOVER001",
				Level:     "error",
				Message:   sarifMessage{Text: fmt.Sprintf("Subdomain takeover: %s CNAME → %s (%s)", t.Subdomain, t.CNAME, t.Service)},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysLoc{ArtifactLocation: sarifArtLoc{URI: "https://" + t.Subdomain}}}},
			})
		}
	}
	for _, c := range corsRes {
		if c.Vulnerable {
			results = append(results, sarifResult{
				RuleID:    "CORS001",
				Level:     "warning",
				Message:   sarifMessage{Text: fmt.Sprintf("CORS misconfiguration at %s: ACAO=%s", c.URL, c.ACAO)},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysLoc{ArtifactLocation: sarifArtLoc{URI: c.URL}}}},
			})
		}
	}
	for _, cr := range credsRes {
		if cr.Found {
			results = append(results, sarifResult{
				RuleID:    "CREDS001",
				Level:     "error",
				Message:   sarifMessage{Text: fmt.Sprintf("Default credentials %s:%s accepted at %s", cr.Username, cr.Password, cr.URL)},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysLoc{ArtifactLocation: sarifArtLoc{URI: cr.URL}}}},
			})
		}
	}
	for _, tm := range tplMatches {
		level := "note"
		switch tm.Severity {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		}
		results = append(results, sarifResult{
			RuleID:    "TEMPLATE001",
			Level:     level,
			Message:   sarifMessage{Text: fmt.Sprintf("[%s] %s matched at %s — %s", tm.TemplateID, tm.Name, tm.URL, tm.Matched)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysLoc{ArtifactLocation: sarifArtLoc{URI: tm.URL}}}},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "recon-x",
				Version:        "2.0.0",
				InformationURI: "https://github.com/bytezora/recon-x",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
