package output

import (
	"encoding/json"
	"os"
	"time"

	"github.com/bytezora/recon-x/internal/axfr"
	"github.com/bytezora/recon-x/internal/buckets"
	"github.com/bytezora/recon-x/internal/dirbust"
	"github.com/bytezora/recon-x/internal/ghsearch"
	"github.com/bytezora/recon-x/internal/httpcheck"
	"github.com/bytezora/recon-x/internal/jsscan"
	"github.com/bytezora/recon-x/internal/openredirect"
	"github.com/bytezora/recon-x/internal/portscan"
	"github.com/bytezora/recon-x/internal/screenshot"
	"github.com/bytezora/recon-x/internal/subdomain"
	"github.com/bytezora/recon-x/internal/tlscheck"
	"github.com/bytezora/recon-x/internal/vulns"
	"github.com/bytezora/recon-x/internal/waf"
	"github.com/bytezora/recon-x/internal/whois"
	"github.com/bytezora/recon-x/internal/asn"
	"github.com/bytezora/recon-x/internal/bypass"
	"github.com/bytezora/recon-x/internal/cors"
	"github.com/bytezora/recon-x/internal/adminpanel"
	"github.com/bytezora/recon-x/internal/defaultcreds"
	"github.com/bytezora/recon-x/internal/emailsec"
	"github.com/bytezora/recon-x/internal/favicon"
	"github.com/bytezora/recon-x/internal/graphql"
	"github.com/bytezora/recon-x/internal/ratelimit"
	"github.com/bytezora/recon-x/internal/sqli"
	"github.com/bytezora/recon-x/internal/takeover"
	"github.com/bytezora/recon-x/internal/templates"
	"github.com/bytezora/recon-x/internal/vhost"
)

type Report struct {
	Target      string               `json:"target"`
	GeneratedAt string               `json:"generated_at"`
	Subdomains  []subdomain.Result   `json:"subdomains"`
	Ports       []portscan.Result    `json:"ports"`
	HTTP        []httpcheck.Result   `json:"http"`
	Vulns       []vulns.Match        `json:"vulns"`
	WAFs        []waf.Result         `json:"wafs"`
	DirHits     []dirbust.Hit        `json:"dir_hits"`
	JSFindings  []jsscan.Finding     `json:"js_findings"`
	GHFindings  []ghsearch.Finding   `json:"github_findings"`
	Buckets     []buckets.Result     `json:"buckets"`
	TLS         []tlscheck.Result    `json:"tls"`
	Redirects   []openredirect.Result `json:"open_redirects"`
	AXFR        []axfr.Result        `json:"axfr"`
	WHOIS       *whois.Result        `json:"whois,omitempty"`
	Screenshots []screenshot.Result  `json:"screenshots"`
	Takeover  []takeover.Result  `json:"takeover"`
	CORS      []cors.Result      `json:"cors"`
	Bypass    []bypass.Result    `json:"bypass"`
	VHosts    []vhost.Result     `json:"vhosts"`
	Favicons  []favicon.Result   `json:"favicons"`
	ASN       []asn.Result       `json:"asn"`
	GraphQL   []graphql.Result   `json:"graphql"`
	EmailSec    *emailsec.Result      `json:"email_security,omitempty"`
	AdminPanel   []adminpanel.Result   `json:"admin_panel,omitempty"`
	SQLi         []sqli.Result         `json:"sqli,omitempty"`
	DefaultCreds []defaultcreds.Result `json:"default_creds,omitempty"`
	RateLimit    []ratelimit.Result    `json:"rate_limit,omitempty"`
	Templates    []templates.Match     `json:"templates,omitempty"`
}

func WriteJSON(
	path, target string,
	subs  []subdomain.Result,
	ports []portscan.Result,
	http  []httpcheck.Result,
	vs    []vulns.Match,
	wafs  []waf.Result,
	dirs  []dirbust.Hit,
	jsf   []jsscan.Finding,
	ghf   []ghsearch.Finding,
	bkts  []buckets.Result,
	tlsr  []tlscheck.Result,
	redir []openredirect.Result,
	axfrr []axfr.Result,
	who   *whois.Result,
	shots []screenshot.Result,
	tkover   []takeover.Result,
	corsR    []cors.Result,
	bypassR  []bypass.Result,
	vhosts   []vhost.Result,
	favicons []favicon.Result,
	asnR     []asn.Result,
	gqlR     []graphql.Result,
	emailR   *emailsec.Result,
	adminPanel   []adminpanel.Result,
	sqliRes      []sqli.Result,
	defaultCreds []defaultcreds.Result,
	rateLimit    []ratelimit.Result,
	tplMatches   []templates.Match,
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
		GHFindings:  ghf,
		Buckets:     bkts,
		TLS:         tlsr,
		Redirects:   redir,
		AXFR:        axfrr,
		WHOIS:       who,
		Screenshots: shots,
		Takeover:  tkover,
		CORS:      corsR,
		Bypass:    bypassR,
		VHosts:    vhosts,
		Favicons:  favicons,
		ASN:       asnR,
		GraphQL:   gqlR,
		EmailSec:    emailR,
		AdminPanel:   adminPanel,
		SQLi:         sqliRes,
		DefaultCreds: defaultCreds,
		RateLimit:    rateLimit,
		Templates:    tplMatches,
	})
}
