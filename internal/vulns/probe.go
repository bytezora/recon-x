package vulns

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
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
	extract func(body string) string
}

var probeSpecs = []probeSpec{
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
	{"/api/v4/version", "gitlab", func(body string) string {
		var m map[string]string
		if json.Unmarshal([]byte(body), &m) != nil {
			return ""
		}
		return m["version"]
	}},
	{"/version", "kubernetes", func(body string) string {
		var m map[string]string
		if json.Unmarshal([]byte(body), &m) != nil {
			return ""
		}
		v := m["gitVersion"]
		return strings.TrimPrefix(v, "v")
	}},
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
{"/rest/api/2/serverInfo", "jira", func(body string) string {
var m map[string]interface{}
if json.Unmarshal([]byte(body), &m) != nil {
return ""
}
if vv, ok := m["version"].(string); ok {
return vv
}
return ""
}},
{"/rest/applinks/1.0/manifest", "confluence", func(body string) string {
var m map[string]interface{}
if json.Unmarshal([]byte(body), &m) != nil {
return ""
}
if vv, ok := m["version"].(string); ok {
return vv
}
return ""
}},
{"/wp-json/", "wordpress", func(body string) string {
var m map[string]interface{}
if json.Unmarshal([]byte(body), &m) != nil {
return ""
}
idx := strings.Index(body, `"generator"`)
if idx < 0 {
return ""
}
sub := body[idx+11:]
for i, c := range sub {
if c == '"' {
sub = sub[i+1:]
break
}
}
end := strings.Index(sub, `"`)
if end < 0 {
return ""
}
gen := sub[:end]
if strings.HasPrefix(gen, "WordPress ") {
return strings.TrimPrefix(gen, "WordPress ")
}
return ""
}},
{"/readme.txt", "wordpress", func(body string) string {
for _, line := range strings.Split(body, "\n") {
if strings.HasPrefix(strings.TrimSpace(line), "Version:") {
return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Version:"))
}
}
return ""
}},
{"/CHANGELOG.txt", "drupal", func(body string) string {
for _, line := range strings.Split(body, "\n") {
line = strings.TrimSpace(line)
if strings.HasPrefix(line, "Drupal ") {
parts := strings.Fields(line)
if len(parts) >= 2 {
return parts[1]
}
}
}
return ""
}},
{"/api/v2.0/systeminfo", "harbor", func(body string) string {
idx := strings.Index(body, `"harbor_version"`)
if idx < 0 {
return ""
}
sub := body[idx+16:]
for i, c := range sub {
if c == '"' {
sub = sub[i+1:]
break
}
}
end := strings.Index(sub, `"`)
if end < 0 {
return ""
}
return strings.TrimPrefix(sub[:end], "v")
}},
{"/administrator/manifests/files/joomla.xml", "joomla", func(body string) string {
re := regexp.MustCompile(`<version>([\d.]+)</version>`)
m := re.FindStringSubmatch(body)
if len(m) > 1 {
return m[1]
}
return ""
}},
{"/realms/master", "keycloak", func(body string) string {
idx := strings.Index(body, `"keycloak-version"`)
if idx < 0 {
return ""
}
sub := body[idx+18:]
for i, c := range sub {
if c == '"' {
sub = sub[i+1:]
break
}
}
end := strings.Index(sub, `"`)
if end < 0 {
return ""
}
return sub[:end]
}},
{"/js/keycloak.js", "keycloak", func(body string) string {
re := regexp.MustCompile(`keycloak-js/([\d.]+)`)
m := re.FindStringSubmatch(body)
if len(m) > 1 {
return m[1]
}
return ""
}},
{"/", "roundcube", func(body string) string {
re := regexp.MustCompile(`Roundcube Webmail ([\d.]+)`)
m := re.FindStringSubmatch(body)
if len(m) > 1 {
return m[1]
}
re2 := regexp.MustCompile(`rcmcssvsn=([\d.]+)`)
m2 := re2.FindStringSubmatch(body)
if len(m2) > 1 {
return m2[1]
}
return ""
}},
{"/service/rest/v1/status/check", "nexus", func(body string) string {
idx := strings.Index(body, `"version"`)
if idx < 0 {
return ""
}
sub := body[idx+9:]
for i, c := range sub {
if c == '"' {
sub = sub[i+1:]
break
}
}
end := strings.Index(sub, `"`)
if end < 0 {
return ""
}
return sub[:end]
}},
{"/api/json?tree=numExecutors", "jenkins", func(body string) string {
return ""
}},
{"/magento_version", "magento", func(body string) string {
return strings.TrimSpace(body)
}},
{"/admin/", "activemq", func(body string) string {
re := regexp.MustCompile(`ActiveMQ ([\d.]+)`)
m := re.FindStringSubmatch(body)
if len(m) > 1 {
return m[1]
}
return ""
}},
{"/remote/info", "fortinet", func(body string) string {
var m map[string]interface{}
if json.Unmarshal([]byte(body), &m) != nil {
return ""
}
if vv, ok := m["version"].(string); ok {
return vv
}
return ""
}},
{"/owa/auth/logon.aspx", "exchange", func(body string) string {
re := regexp.MustCompile(`owa/auth/([\d.]+)/`)
m := re.FindStringSubmatch(body)
if len(m) > 1 {
return m[1]
}
return ""
}},
{"/zimbra/", "zimbra", func(body string) string {
re := regexp.MustCompile(`Zimbra[/ ]([\d.]+)`)
m := re.FindStringSubmatch(body)
if len(m) > 1 {
return m[1]
}
return ""
}},
	{"/api/health", "grafana", func(body string) string {
		var m map[string]string
		if json.Unmarshal([]byte(body), &m) != nil {
			return ""
		}
		return m["version"]
	}},
}

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
