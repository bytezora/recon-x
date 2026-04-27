package emailsec

import (
	"net"
	"strings"
)

type Result struct {
	Domain      string `json:"domain"`
	SPF         string `json:"spf"`
	SPFStrict   bool   `json:"spf_strict"`
	DMARC       string `json:"dmarc"`
	DMARCPolicy string `json:"dmarc_policy"`
	DKIM        string `json:"dkim"`
	Spoofable   bool   `json:"spoofable"`
}

func Check(domain string) (*Result, error) {
	r := &Result{Domain: domain}

	txts, err := net.LookupTXT(domain)
	if err == nil {
		for _, t := range txts {
			if strings.HasPrefix(t, "v=spf1") {
				r.SPF = t
				r.SPFStrict = strings.Contains(t, "-all") || strings.Contains(t, "~all")
				break
			}
		}
	}

	dmarcTxts, err := net.LookupTXT("_dmarc." + domain)
	if err == nil {
		for _, t := range dmarcTxts {
			if strings.HasPrefix(t, "v=DMARC1") {
				r.DMARC = t
				for _, part := range strings.Split(t, ";") {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, "p=") {
						r.DMARCPolicy = strings.TrimPrefix(part, "p=")
					}
				}
				break
			}
		}
	}

	dkimSelectors := []string{"default", "google", "mail"}
	for _, sel := range dkimSelectors {
		dkimTxts, err := net.LookupTXT(sel + "._domainkey." + domain)
		if err == nil {
			for _, t := range dkimTxts {
				if strings.Contains(t, "v=DKIM1") {
					r.DKIM = t
					break
				}
			}
		}
		if r.DKIM != "" {
			break
		}
	}

	r.Spoofable = r.SPF == "" || r.DMARCPolicy == "none" || (r.DMARC == "" && !r.SPFStrict)
	return r, nil
}
