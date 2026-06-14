package sanitize

import (
	"crypto/sha256"
	"fmt"

	"github.com/bytezora/recon-x/internal/engine"
)

func Results(res *engine.Results, showSecrets bool, redactPercent int) {
	if res == nil || showSecrets {
		return
	}
	for i := range res.JS {
		if res.JS[i].Kind == "secret" {
			res.JS[i].Value = Secret(res.JS[i].Value, redactPercent)
		}
	}
	for i := range res.DefaultCreds {
		res.DefaultCreds[i].Password = Secret(res.DefaultCreds[i].Password, redactPercent)
	}
	for i := range res.Findings {
		if res.Findings[i].Type == "default-creds" {
			res.Findings[i].Title = "Default Credentials Accepted"
			res.Findings[i].Evidence = "Default credentials were accepted; password redacted in safe output mode."
		}
	}
}

func Secret(value string, redactPercent int) string {
	if value == "" {
		return ""
	}
	if redactPercent <= 0 {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	hash := fmt.Sprintf("%x", sum[:])[:12]
	if redactPercent >= 100 || len(value) <= 6 {
		return fmt.Sprintf("[REDACTED len=%d sha256_12=%s]", len(value), hash)
	}

	keep := len(value) * (100 - redactPercent) / 100
	if keep < 2 {
		keep = 2
	}
	if keep >= len(value) {
		keep = len(value) - 1
	}
	prefix := keep / 2
	suffix := keep - prefix
	return fmt.Sprintf("%s...[REDACTED sha256_12=%s]...%s", value[:prefix], hash, value[len(value)-suffix:])
}
