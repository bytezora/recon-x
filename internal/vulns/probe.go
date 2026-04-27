// Package vulns — probe.go tries well-known version endpoints on HTTP services
// to extract product/version information that may not appear in headers or body of /.
package vulns

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var probeClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type probeSpec struct {
	path    string
	product string
	extract func(body string) string // returns version or ""
}

var probeSpecs = []probeSpec{
	// Spring Boot actuator — reports Log4j version, Spring version, etc.
	{"/actuator/info", "springboot", func(body string) string {
		var m map[string]interface{}
		if json.Unmarshal([]byte(body), &m) != nil {
			return ""
		}
		if build, ok := m["build"].(map[string]interface{}); ok {
			if v, ok := build["version"].(string); ok {
				return v
			}
		}
		return ""
	}},
	{"/actuator/info", "log4j", func(body string) string {
		idx := strings.Index(body, `"log4j-core"`)
		if idx < 0 {
			return ""
		}
		sub := body[idx:]
		idx2 := strings.Index(sub, `"version"`)
		if idx2 < 0 {
			return ""
		}
		sub = sub[idx2+9:]
		idx3 := strings.Index(sub, `"`)
		if idx3 < 0 {
			return ""
		}
		sub = sub[idx3+1:]
		idx4 := strings.Index(sub, `"`)
		if idx4 < 0 {
			return ""
		}
		return sub[:idx4]
	}},
	// GitLab version API
	{"/api/v4/version", "gitlab", func(body string) string {
		var m map[string]string
		if json.Unmarshal([]byte(body), &m) != nil {
			return ""
		}
		return m["version"]
	}},
	// Kubernetes API version
	{"/version", "kubernetes", func(body string) string {
		var m map[string]string
		if json.Unmarshal([]byte(body), &m) != nil {
			return ""
		}
		v := m["gitVersion"]
		return strings.TrimPrefix(v, "v")
	}},
	// Elasticsearch cluster stats
	{"/_cluster/stats", "elasticsearch", func(body string) string {
		idx := strings.Index(body, `"number"`)
		if idx < 0 {
			return ""
		}
		sub := body[idx+8:]
		idx2 := strings.Index(sub, `"`)
		if idx2 < 0 {
			return ""
		}
		sub = sub[idx2+1:]
		idx3 := strings.Index(sub, `"`)
		if idx3 < 0 {
			return ""
		}
		return sub[:idx3]
	}},
	// Apache Solr info
	{"/solr/admin/info/system?wt=json", "solr", func(body string) string {
		idx := strings.Index(body, `"solr-spec-version"`)
		if idx < 0 {
			return ""
		}
		sub := body[idx+19:]
		idx2 := strings.Index(sub, `"`)
		if idx2 < 0 {
			return ""
		}
		sub = sub[idx2+1:]
		idx3 := strings.Index(sub, `"`)
		if idx3 < 0 {
			return ""
		}
		return sub[:idx3]
	}},
	// Nexus
	{"/service/rest/v1/status/check", "nexus", func(body string) string { return "" }},
	// Grafana API
	{"/api/health", "grafana", func(body string) string {
		var m map[string]string
		if json.Unmarshal([]byte(body), &m) != nil {
			return ""
		}
		return m["version"]
	}},
}

// ProbeVersionEndpoints tries version-disclosure endpoints and returns additional detected products.
func ProbeVersionEndpoints(scheme, host string, port int) []Match {
	var all []Match
	base := scheme + "://" + host
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		base += ":" + strconv.Itoa(port)
	}
	for _, spec := range probeSpecs {
		resp, err := probeClient.Get(base + spec.path)
		if err != nil || resp.StatusCode >= 500 {
			if err == nil {
				resp.Body.Close()
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		if err != nil {
			continue
		}
		ver := spec.extract(string(body))
		if ver == "" {
			continue
		}
		d := detected{product: spec.product, ver: parseVersion(ver), raw: ver}
		all = append(all, buildMatches(host, port, ver, []detected{d})...)
	}
	return all
}
