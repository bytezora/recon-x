// Package output handles serialization of scan results to JSON.
package output

import (
	"encoding/json"
	"os"
	"time"

	"github.com/bytezora/recon-x/internal/dirbust"
	"github.com/bytezora/recon-x/internal/httpcheck"
	"github.com/bytezora/recon-x/internal/jsscan"
	"github.com/bytezora/recon-x/internal/portscan"
	"github.com/bytezora/recon-x/internal/subdomain"
	"github.com/bytezora/recon-x/internal/vulns"
	"github.com/bytezora/recon-x/internal/waf"
)

// Report is the top-level JSON structure written to disk.
type Report struct {
	Target      string             `json:"target"`
	GeneratedAt string             `json:"generated_at"`
	Subdomains  []subdomain.Result `json:"subdomains"`
	Ports       []portscan.Result  `json:"ports"`
	HTTP        []httpcheck.Result `json:"http"`
	Vulns       []vulns.Match      `json:"vulns"`
	WAFs        []waf.Result       `json:"wafs"`
	DirHits     []dirbust.Hit      `json:"dir_hits"`
	JSFindings  []jsscan.Finding   `json:"js_findings"`
}

// WriteJSON serialises all scan results to a JSON file at path.
func WriteJSON(
	path, target string,
	subs  []subdomain.Result,
	ports []portscan.Result,
	http  []httpcheck.Result,
	vs    []vulns.Match,
	wafs  []waf.Result,
	dirs  []dirbust.Hit,
	jsf   []jsscan.Finding,
) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(Report{
		Target:      target,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Subdomains:  subs,
		Ports:       ports,
		HTTP:        http,
		Vulns:       vs,
		WAFs:        wafs,
		DirHits:     dirs,
		JSFindings:  jsf,
	})
}

