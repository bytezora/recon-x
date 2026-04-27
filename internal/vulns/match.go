// Package vulns detects known CVEs by matching service banners and HTTP response
// headers against an embedded database with precise version-range comparisons.
//
// No external API calls. No rate limits. Works fully offline.
package vulns

import (
	"net/http"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
)

// Match represents a CVE finding for a specific host and service.
type Match struct {
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Banner      string  `json:"banner"`
	CVE         string  `json:"cve"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Link        string  `json:"link"`
}

type version struct{ parts []int }

func (v version) valid() bool { return len(v.parts) > 0 }

// parseVersion converts "7.4.3", "8.9p1", "1.18.0-ubuntu2" → {[7,4,3]}.
// Letters and dashes after the first numeric component are stripped.
func parseVersion(s string) version {
	s = strings.TrimPrefix(s, "v")
	end := len(s)
	for i, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			end = i
			break
		}
	}
	s = strings.TrimRight(s[:end], ".")
	if s == "" {
		return version{}
	}
	parts := strings.Split(s, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	return version{parts: nums}
}

// cmp returns -1, 0, or +1.
func (v version) cmp(o version) int {
	n := len(v.parts)
	if len(o.parts) > n {
		n = len(o.parts)
	}
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(v.parts) {
			a = v.parts[i]
		}
		if i < len(o.parts) {
			b = o.parts[i]
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}
	return 0
}

func (v version) gte(o version) bool { return v.cmp(o) >= 0 }
func (v version) lte(o version) bool { return v.cmp(o) <= 0 }

// v is a shorthand for inline version literals inside the database.
func v(s string) version { return parseVersion(s) }

type extractor struct {
	product string
	re      *regexp.Regexp // version captured in group 1
}

var bannerExtractors = []extractor{
	// SSH
	{"openssh", regexp.MustCompile(`OpenSSH[_/](\d+\.\d+[\d.]*)`)},
	// HTTP servers (raw TCP banner from a HEAD request)
	{"apache", regexp.MustCompile(`Apache/([\d.]+)`)},
	{"nginx", regexp.MustCompile(`nginx/([\d.]+)`)},
	{"iis", regexp.MustCompile(`Microsoft-IIS/([\d.]+)`)},
	{"lighttpd", regexp.MustCompile(`lighttpd/([\d.]+)`)},
	{"tomcat", regexp.MustCompile(`Apache Tomcat/([\d.]+)`)},
	// FTP
	{"vsftpd", regexp.MustCompile(`vsftpd\s+([\d.]+)`)},
	{"proftpd", regexp.MustCompile(`ProFTPD\s+([\d.]+)`)},
	// SMTP
	{"exim", regexp.MustCompile(`Exim\s+([\d.]+)`)},
	{"sendmail", regexp.MustCompile(`Sendmail\s+([\d.]+)`)},
	// Databases
	{"mysql",      regexp.MustCompile(`([\d.]+)-[Mm]y[Ss][Qq][Ll]`)},
	{"redis",      regexp.MustCompile(`Redis server v=([\d.]+)`)},
	{"mongodb",    regexp.MustCompile(`MongoDB\s+([\d.]+)`)},
	{"postgresql", regexp.MustCompile(`PostgreSQL\s+([\d.]+)`)},
	// Other
	{"samba",      regexp.MustCompile(`Samba\s+([\d.]+)`)},
	{"php",        regexp.MustCompile(`PHP/([\d.]+)`)},
	{"solr",       regexp.MustCompile(`(?i)Apache[ -]Solr[/ ]([\d.]+)`)},
	{"coldfusion", regexp.MustCompile(`(?i)ColdFusion[/ ]([\d.]+)`)},
	{"memcached",  regexp.MustCompile(`(?i)VERSION ([\d.]+)`)},
	{"zookeeper",  regexp.MustCompile(`(?i)Zookeeper version: ([\d.]+[^,\s]*)`)},
	{"activemq",   regexp.MustCompile(`(?i)ActiveMQ[/ ]([\d.]+)`)},
	{"weblogic",   regexp.MustCompile(`(?i)WebLogic Server ([\d.]+)`)},
	{"jboss",      regexp.MustCompile(`(?i)JBoss[/ ]([\d.]+)`)},
	{"glassfish",  regexp.MustCompile(`(?i)GlassFish[/ ]([\d.]+)`)},
	{"openssl",    regexp.MustCompile(`OpenSSL/([\d.]+[a-z]?)`)},
}

var headerExtractors = []struct {
	header       string
	product      string
	re           *regexp.Regexp
	presenceOnly bool // true = any non-empty header value fires ALL CVEs for product
}{
	{"Server", "apache", regexp.MustCompile(`Apache/([\d.]+)`), false},
	{"Server", "nginx", regexp.MustCompile(`nginx/([\d.]+)`), false},
	{"Server", "iis", regexp.MustCompile(`Microsoft-IIS/([\d.]+)`), false},
	{"Server", "lighttpd", regexp.MustCompile(`lighttpd/([\d.]+)`), false},
	{"Server", "tomcat", regexp.MustCompile(`Apache Tomcat/([\d.]+)`), false},
	{"X-Powered-By", "php", regexp.MustCompile(`PHP/([\d.]+)`), false},
	{"X-Generator", "wordpress", regexp.MustCompile(`WordPress ([\d.]+)`), false},
	{"X-Jenkins", "jenkins", regexp.MustCompile(`([\d.]+)`), false},
	{"X-Jenkins-Session", "jenkins", regexp.MustCompile(`.+`), true}, // presence-only: fires all Jenkins CVEs
	{"Server",                "grafana", regexp.MustCompile(`(?i)Grafana/([\d.]+)`),   false},
	{"X-Generator",           "drupal",  regexp.MustCompile(`(?i)Drupal\s+([\d.]+)`), false},
	{"X-Drupal-Cache",        "drupal",  regexp.MustCompile(`.+`),                     true},
	{"X-Application-Context",        "spring",     regexp.MustCompile(`.+`),                         true},
	// Atlassian Confluence
	{"X-Confluence-Request-Time",    "confluence", regexp.MustCompile(`.+`),                         true},
	{"X-Confluence-Cluster-Node-Id", "confluence", regexp.MustCompile(`.+`),                         true},
	// Atlassian Jira
	{"X-AREQUESTID",                 "jira",       regexp.MustCompile(`.+`),                         true},
	// Adobe ColdFusion
	{"X-Powered-By",                 "coldfusion", regexp.MustCompile(`(?i)ColdFusion/([\d.]+)`),   false},
	{"X-Powered-By",                 "coldfusion", regexp.MustCompile(`(?i)^ColdFusion$`),           true},
	// F5 BIG-IP — Server header and BIGipServer cookie
	{"Server",                       "bigip",      regexp.MustCompile(`(?i)BigIP`),                  true},
	{"Set-Cookie",                   "bigip",      regexp.MustCompile(`(?i)BIGipServer`),             true},
	// Citrix ADC / NetScaler — NSC_ session cookie is a reliable indicator
	{"Set-Cookie",                   "citrix",     regexp.MustCompile(`(?i)NSC_[a-zA-Z0-9]`),        true},
	// Apache Solr via Server header
	{"Server",                       "solr",       regexp.MustCompile(`(?i)Solr/([\d.]+)`),          false},
	// Microsoft Exchange
	{"X-OWA-Version",           "exchange",  regexp.MustCompile(`([\d.]+)`),                false},
	{"X-MS-Diagnostics",        "exchange",  regexp.MustCompile(`.+`),                       true},
	// GitLab
	{"X-GitLab-Meta-Caller-Id", "gitlab",    regexp.MustCompile(`.+`),                       true},
	{"X-Recruiting",            "gitlab",    regexp.MustCompile(`.+`),                       true},
	// Nexus Repository
	{"Server",                  "nexus",     regexp.MustCompile(`(?i)Nexus/([\d.]+)`),       false},
	// Harbor container registry
	{"Server",                  "harbor",    regexp.MustCompile(`(?i)Harbor/([\d.]+)`),      false},
}

var bodyExtractors = []struct {
	product      string
	re           *regexp.Regexp
	presenceOnly bool
}{
	{"wordpress",     regexp.MustCompile(`(?i)WordPress\s+([\d.]+)`), false},
	{"drupal",        regexp.MustCompile(`(?i)Drupal\s+([\d.]+)`), false},
	{"struts",        regexp.MustCompile(`(?i)Apache[ -]Struts[/ ]([\d.]+)`), false},
	{"spring",        regexp.MustCompile(`(?i)Spring[ -]Framework[/ ]([\d.]+)`), false},
	{"grafana",       regexp.MustCompile(`"version"\s*:\s*"([\d.]+)"`), false},
	{"elasticsearch", regexp.MustCompile(`"number"\s*:\s*"([\d.]+)"`), false},
	// Atlassian Confluence — version from meta tag or page content
	{"confluence", regexp.MustCompile(`(?i)<meta[^>]+name=["']ajs-version-number["'][^>]*content=["']([\d.]+)`), false},
	{"confluence", regexp.MustCompile(`(?i)Confluence[/ ]([\d.]+)`), false},
	{"confluence", regexp.MustCompile(`(?i)com-atlassian-confluence`), true},
	// Atlassian Jira — presence via application-name meta, version from page text
	{"jira", regexp.MustCompile(`(?i)<meta[^>]+name=["']application-name["'][^>]*content=["']JIRA`), true},
	{"jira", regexp.MustCompile(`(?i)Atlassian Jira[^<(]*([\d]+\.[\d]+\.[\d.]*)`), false},
	// Apache Solr — version from admin UI or title
	{"solr", regexp.MustCompile(`(?i)Apache Solr[/ ]([\d.]+)`), false},
	{"solr", regexp.MustCompile(`(?i)<title>[^<]*Apache Solr`), true},
	// Log4j — via Spring Boot actuator /actuator/info or error stacktraces
	{"log4j", regexp.MustCompile(`"log4j-core"[^}]*"version"\s*:\s*"([\d.]+)`), false},
	{"log4j", regexp.MustCompile(`log4j-core-([\d.]+)\.jar`), false},
	// VMware vCenter — version string or presence via client title
	{"vmware", regexp.MustCompile(`(?i)VMware vCenter Server ([\d.]+)`), false},
	{"vmware", regexp.MustCompile(`(?i)vSphere (Web )?Client`), true},
	// F5 BIG-IP — presence via page title or branding
	{"bigip", regexp.MustCompile(`(?i)<title>[^<]*BIG-IP`), true},
	{"bigip", regexp.MustCompile(`(?i)F5 Networks`), true},
	// Adobe ColdFusion — version from error pages or presence
	{"coldfusion", regexp.MustCompile(`(?i)ColdFusion[/ ]([\d.]+)`), false},
	{"coldfusion", regexp.MustCompile(`(?i)Adobe ColdFusion`), true},
	// GitLab
	{"gitlab",     regexp.MustCompile(`(?i)GitLab[/ ]([\d.]+)`), false},
	{"gitlab",     regexp.MustCompile(`(?i)gitlab-instance`), true},
	// Nexus Repository Manager
	{"nexus",      regexp.MustCompile(`(?i)Nexus Repository Manager\s+([\d.]+)`), false},
	{"nexus",      regexp.MustCompile(`(?i)Sonatype Nexus`), true},
	// Microsoft Exchange / OWA
	{"exchange",   regexp.MustCompile(`(?i)Microsoft Exchange`), true},
	{"exchange",   regexp.MustCompile(`(?i)Outlook Web App`), true},
	// Zimbra
	{"zimbra",     regexp.MustCompile(`(?i)Zimbra[/ ]([\d.]+)`), false},
	{"zimbra",     regexp.MustCompile(`(?i)Zimbra Web Client`), true},
	// Joomla
	{"joomla",     regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]*content=["']Joomla[! ]([\d.]+)`), false},
	{"joomla",     regexp.MustCompile(`(?i)/components/com_content/`), true},
	// Magento / Adobe Commerce
	{"magento",    regexp.MustCompile(`(?i)Magento[/ ]([\d.]+)`), false},
	{"magento",    regexp.MustCompile(`(?i)var BLANK_URL = ['"][^'"]*\/pub\/`), true},
	// Roundcube Webmail
	{"roundcube",  regexp.MustCompile(`(?i)Roundcube Webmail[/ ]*([\d.]+)`), false},
	{"roundcube",  regexp.MustCompile(`(?i)Roundcube Webmail`), true},
	// Keycloak
	{"keycloak",   regexp.MustCompile(`(?i)Keycloak[/ ]*([\d.]+)`), false},
	{"keycloak",   regexp.MustCompile(`(?i)keycloak-theme`), true},
	// Apache ActiveMQ admin console
	{"activemq",   regexp.MustCompile(`(?i)Apache ActiveMQ[/ ]*([\d.]+)`), false},
	{"activemq",   regexp.MustCompile(`(?i)activemq`), true},
	// WebLogic
	{"weblogic",   regexp.MustCompile(`(?i)WebLogic Server ([\d.]+)`), false},
	{"weblogic",   regexp.MustCompile(`(?i)WebLogic`), true},
	// Fortinet FortiGate SSL-VPN
	{"fortinet",   regexp.MustCompile(`(?i)FortiGate`), true},
	{"fortinet",   regexp.MustCompile(`(?i)FortiOS[/ ]*([\d.]+)`), false},
	// Pulse Secure / Ivanti Connect Secure
	{"pulse",      regexp.MustCompile(`(?i)Pulse (Connect|Secure)[/ ]*([\d.]+)`), false},
	{"pulse",      regexp.MustCompile(`(?i)(Pulse Connect Secure|Ivanti Connect Secure)`), true},
	// Harbor container registry
	{"harbor",     regexp.MustCompile(`(?i)Harbor[/ ]*([\d.]+)`), false},
	{"harbor",     regexp.MustCompile(`(?i)goharbor`), true},
	// Kubernetes dashboard / API
	{"kubernetes", regexp.MustCompile(`(?i)"gitVersion"\s*:\s*"v([\d.]+)`), false},
	{"kubernetes", regexp.MustCompile(`(?i)Kubernetes`), true},
	// OpenSSL (in error pages or banners)
	{"openssl",    regexp.MustCompile(`OpenSSL/([\d.]+[a-z]?)`), false},
}

type detected struct {
	product      string
	ver          version
	raw          string
	presenceOnly bool // header present but no version extractable
}

func fromBanner(banner string) []detected {
	if banner == "" {
		return nil
	}
	var out []detected
	seen := make(map[string]bool)
	for _, ex := range bannerExtractors {
		m := ex.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		raw := ""
		if len(m) > 1 {
			raw = m[1]
		}
		key := ex.product + "/" + raw
		if !seen[key] {
			seen[key] = true
			out = append(out, detected{product: ex.product, ver: parseVersion(raw), raw: raw})
		}
	}
	return out
}

func fromHeaders(h http.Header) []detected {
	if h == nil {
		return nil
	}
	var out []detected
	seen := make(map[string]bool)
	for _, ex := range headerExtractors {
		// Use all values for multi-value headers (critical for Set-Cookie)
		vals := h[textproto.CanonicalMIMEHeaderKey(ex.header)]
		if len(vals) == 0 {
			continue
		}
		val := strings.Join(vals, "; ")
		if ex.presenceOnly {
			// Check regex even for presenceOnly: distinguishes products on shared headers (Set-Cookie)
			if !ex.re.MatchString(val) {
				continue
			}
			key := ex.product + "/presence"
			if !seen[key] {
				seen[key] = true
				out = append(out, detected{product: ex.product, presenceOnly: true})
			}
			continue
		}
		m := ex.re.FindStringSubmatch(val)
		if m == nil {
			continue
		}
		raw := ""
		if len(m) > 1 {
			raw = m[1]
		}
		key := ex.product + "/" + raw
		if !seen[key] {
			seen[key] = true
			out = append(out, detected{product: ex.product, ver: parseVersion(raw), raw: raw})
		}
	}
	return out
}

func fromBody(body string) []detected {
	if body == "" {
		return nil
	}
	var out []detected
	seen := make(map[string]bool)
	for _, ex := range bodyExtractors {
		m := ex.re.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		if ex.presenceOnly {
			key := ex.product + "/presence"
			if !seen[key] {
				seen[key] = true
				out = append(out, detected{product: ex.product, presenceOnly: true})
			}
			continue
		}
		raw := ""
		if len(m) > 1 {
			raw = m[1]
		}
		key := ex.product + "/" + raw
		if !seen[key] {
			seen[key] = true
			out = append(out, detected{product: ex.product, ver: parseVersion(raw), raw: raw})
		}
	}
	return out
}

const nvdBase = "https://nvd.nist.gov/vuln/detail/"

type cveEntry struct {
	product  string
	cve      string
	cvss     float64
	severity string
	desc     string
	minVer   version // inclusive lower bound
	maxVer   version // inclusive upper bound
}

// inRange returns true when minVer <= d.ver <= maxVer.
func inRange(e cveEntry, d detected) bool {
	if !d.ver.valid() {
		return false
	}
	return d.ver.gte(e.minVer) && d.ver.lte(e.maxVer)
}

// db is the embedded CVE database sorted by product.
// Sources: NVD, CISA KEV, CVEdetails.com — all entries public knowledge.
var db = []cveEntry{

	{"apache", "CVE-2023-25690", 9.8, "CRITICAL", "HTTP request smuggling via mod_proxy rewrite (≤ 2.4.55)", v("2.0"), v("2.4.55")},
	{"apache", "CVE-2022-31813", 9.8, "CRITICAL", "X-Forwarded-* header bypass in mod_proxy (≤ 2.4.53)", v("2.0"), v("2.4.53")},
	{"apache", "CVE-2022-22720", 9.8, "CRITICAL", "HTTP request smuggling via Keep-Alive (≤ 2.4.52)", v("2.0"), v("2.4.52")},
	{"apache", "CVE-2021-42013", 9.8, "CRITICAL", "Path traversal + RCE bypass in mod_cgi (2.4.50)", v("2.4.50"), v("2.4.50")},
	{"apache", "CVE-2021-41773", 9.8, "CRITICAL", "Path traversal + RCE in mod_cgi (2.4.49)", v("2.4.49"), v("2.4.49")},
	{"apache", "CVE-2021-40438", 9.0, "CRITICAL", "SSRF via crafted URI in mod_proxy (≤ 2.4.48)", v("2.0"), v("2.4.48")},
	{"apache", "CVE-2017-9798", 7.5, "HIGH", "Optionsbleed — use-after-free in OPTIONS method (≤ 2.4.26)", v("2.2"), v("2.4.26")},
	{"apache", "CVE-2017-7679", 9.8, "CRITICAL", "Heap buffer overflow in mod_mime (≤ 2.2.32 / ≤ 2.4.25)", v("2.2"), v("2.4.25")},
	{"apache", "CVE-2017-7668", 9.8, "CRITICAL", "ap_find_token buffer overread (≤ 2.2.32 / ≤ 2.4.25)", v("2.2"), v("2.4.25")},
	{"apache", "CVE-2024-38476", 9.1, "CRITICAL", "Malicious backend response causes HTTP response splitting (2.4.0–2.4.59)", v("2.4.0"), v("2.4.59")},
	{"apache", "CVE-2024-38472", 7.5, "HIGH",     "SSRF via UNC-path resolution on Windows (2.4.0–2.4.59)", v("2.4.0"), v("2.4.59")},
	{"apache", "CVE-2023-45802", 5.9, "MEDIUM",   "HTTP/2 stream reset — memory not reclaimed, DoS (2.4.17–2.4.57)", v("2.4.17"), v("2.4.57")},

	{"nginx", "CVE-2021-23017", 7.7, "HIGH", "1-byte heap overwrite via crafted DNS response (≤ 1.20.0)", v("0.6.18"), v("1.20.0")},
	{"nginx", "CVE-2017-7529", 7.5, "HIGH", "Integer overflow in range filter — info disclosure (≤ 1.13.2)", v("0.5.6"), v("1.13.2")},
	{"nginx", "CVE-2016-0746", 9.8, "CRITICAL", "Use-after-free in CNAME resolver (≤ 1.9.13)", v("0.1"), v("1.9.13")},
	{"nginx", "CVE-2016-0742", 7.5, "HIGH", "Invalid pointer dereference in CNAME resolver (≤ 1.9.13)", v("0.1"), v("1.9.13")},
	{"nginx", "CVE-2013-2028", 9.8, "CRITICAL", "Stack buffer overflow via chunked encoding (1.3.9–1.4.0)", v("1.3.9"), v("1.4.0")},

	{"openssh", "CVE-2024-6387", 8.1, "HIGH", "regreSSHion — RCE signal handler race in sshd (8.5–9.7)", v("8.5"), v("9.7")},
	{"openssh", "CVE-2023-48795", 5.9, "MEDIUM", "Terrapin — SSH protocol downgrade via HMAC truncation (< 9.6)", v("0.1"), v("9.5")},
	{"openssh", "CVE-2023-38408", 9.8, "CRITICAL", "RCE via ssh-agent forwarding with PKCS#11 (< 9.3p2)", v("0.1"), v("9.3")},
	{"openssh", "CVE-2021-28041", 7.1, "HIGH", "Double-free in ssh-agent (8.2)", v("8.2"), v("8.2")},
	{"openssh", "CVE-2018-15473", 5.3, "MEDIUM", "Username enumeration via auth timing side-channel (< 7.7)", v("0.1"), v("7.6")},
	{"openssh", "CVE-2016-10012", 7.8, "HIGH", "Privilege escalation in shared-memory manager (< 7.4)", v("0.1"), v("7.3")},
	{"openssh", "CVE-2016-10009", 7.3, "HIGH", "Privilege escalation via PKCS11 module load (< 7.4)", v("0.1"), v("7.3")},
	{"openssh", "CVE-2016-6210", 5.9, "MEDIUM", "Username enumeration via bcrypt/SHA256 timing (< 7.3)", v("0.1"), v("7.2")},

	{"php", "CVE-2024-4577", 9.8, "CRITICAL", "Arg injection in PHP-CGI on Windows via charset param (< 8.1.29/8.2.20/8.3.8)", v("5.0"), v("8.2.19")},
	{"php", "CVE-2023-3824", 9.8, "CRITICAL", "Stack buffer overflow in PHAR reader (< 8.0.30/8.1.23/8.2.10)", v("5.0"), v("8.1.22")},
	{"php", "CVE-2022-31625", 8.1, "HIGH", "Uninitialized variable use in PostgreSQL extension (< 8.1.7)", v("5.0"), v("8.1.6")},
	{"php", "CVE-2021-21703", 7.0, "HIGH", "Local privilege escalation via FPM main socket (< 7.3.31/7.4.24/8.0.11)", v("5.0"), v("8.0.10")},
	{"php", "CVE-2019-11043", 9.8, "CRITICAL", "RCE via env_path_info underflow in PHP-FPM (< 7.1.33/7.2.24/7.3.11)", v("7.0"), v("7.3.10")},
	{"php", "CVE-2018-19518", 7.5, "HIGH", "IMAP UW-IMAP toolkit command injection (< 7.3.0)", v("5.0"), v("7.2.99")},
	{"php", "CVE-2017-11628", 7.8, "HIGH", "Stack buffer overflow in zend_ini_do_op (< 7.1.7)", v("5.0"), v("7.1.6")},

	{"vsftpd", "CVE-2011-2523", 10.0, "CRITICAL", "Backdoor in vsftpd 2.3.4 — remote root shell on :6200", v("2.3.4"), v("2.3.4")},

	{"proftpd", "CVE-2019-12815", 9.8, "CRITICAL", "Arbitrary file copy via mod_copy unauthenticated (< 1.3.6b)", v("1.0"), v("1.3.6")},
	{"proftpd", "CVE-2015-3306", 10.0, "CRITICAL", "Unauthenticated file read/write via mod_copy (1.3.5)", v("1.3.5"), v("1.3.5")},
	{"proftpd", "CVE-2021-46854", 7.5, "HIGH", "Heap use-after-free in RADIUS authenticator (< 1.3.7c)", v("1.0"), v("1.3.7")},

	{"exim", "CVE-2020-28028", 9.8, "CRITICAL", "Heap buffer overflow in receive_add_recipient (< 4.94.2)", v("4.0"), v("4.94.1")},
	{"exim", "CVE-2020-28020", 9.8, "CRITICAL", "Integer overflow in receive_add_recipient (< 4.94.2)", v("4.0"), v("4.94.1")},
	{"exim", "CVE-2020-28017", 9.8, "CRITICAL", "Integer overflow in receive_msg() (< 4.94.2)", v("4.0"), v("4.94.1")},
	{"exim", "CVE-2019-10149", 9.8, "CRITICAL", "RCE via MAIL FROM in Exim (4.87–4.91)", v("4.87"), v("4.91")},

	{"iis", "CVE-2022-21907", 9.8, "CRITICAL", "RCE via HTTP trailer header in HTTP.sys (IIS 10.0)", v("10.0"), v("10.0")},
	{"iis", "CVE-2021-31166", 9.8, "CRITICAL", "RCE in HTTP protocol stack — wormable (IIS 10.0)", v("10.0"), v("10.0")},
	{"iis", "CVE-2017-7269", 9.8, "CRITICAL", "Buffer overflow in WebDAV ScStoragePathFromUrl (IIS 6.0)", v("6.0"), v("6.0")},
	{"iis", "CVE-2015-1635", 9.8, "CRITICAL", "RCE via HTTP Range header (IIS 7.5/8.0/8.5)", v("7.5"), v("8.5")},

	{"tomcat", "CVE-2020-1938", 9.8, "CRITICAL", "Ghostcat — AJP LFI/RCE in AJP connector (< 9.0.31/8.5.51/7.0.100)", v("6.0"), v("9.0.30")},
	{"tomcat", "CVE-2019-0232", 9.8, "CRITICAL", "RCE via CGI servlet on Windows (< 9.0.17/8.5.39)", v("7.0"), v("9.0.16")},
	{"tomcat", "CVE-2017-12617", 9.8, "CRITICAL", "RCE via partial PUT request (< 8.5.22/9.0.0.M26)", v("7.0"), v("8.5.21")},
	{"tomcat", "CVE-2022-42252", 7.5, "HIGH", "HTTP request smuggling via invalid Content-Length (< 9.0.68/10.0.27)", v("8.0"), v("9.0.67")},
	{"tomcat", "CVE-2021-33037", 5.3, "MEDIUM", "HTTP request smuggling via invalid Transfer-Encoding (< 8.5.69/9.0.48/10.1.0-M3)", v("8.0"), v("9.0.47")},

	{"redis", "CVE-2022-0543", 10.0, "CRITICAL", "Lua sandbox escape via package.loaded in Debian builds (< 6.2)", v("2.0"), v("6.1.99")},
	{"redis", "CVE-2022-35977", 5.5, "MEDIUM", "Integer overflow in SRANDMEMBER/ZRANDMEMBER (< 7.0.7)", v("6.0"), v("7.0.6")},
	{"redis", "CVE-2023-28856", 6.5, "MEDIUM", "Authenticated crash via XAUTOCLAIM (< 7.0.11)", v("7.0"), v("7.0.10")},
	{"redis", "CVE-2021-32761", 6.5, "MEDIUM", "Integer overflow in BITFIELD on 32-bit builds (< 6.2.5)", v("2.0"), v("6.2.4")},

	{"mysql", "CVE-2016-6662", 9.8, "CRITICAL", "Remote root via config file injection (< 5.5.53/5.6.34/5.7.16)", v("5.0"), v("5.7.15")},
	{"mysql", "CVE-2016-6663", 7.0, "HIGH", "Race condition privilege escalation (< 5.5.52)", v("5.0"), v("5.5.51")},
	{"mysql", "CVE-2021-35604", 7.7, "HIGH", "InnoDB privilege escalation (< 8.0.27)", v("8.0"), v("8.0.26")},

	{"samba", "CVE-2020-1472", 10.0, "CRITICAL", "Zerologon — full domain takeover via NetLogon crypto flaw (< 4.10.18)", v("4.0"), v("4.10.17")},
	{"samba", "CVE-2021-44142", 9.9, "CRITICAL", "Heap OOB write in VFS module — RCE (< 4.13.17/4.14.12/4.15.5)", v("4.0"), v("4.15.4")},
	{"samba", "CVE-2017-7494", 9.8, "CRITICAL", "EternalRed — RCE via malicious shared library (3.5.0–4.6.4)", v("3.5"), v("4.6.4")},

	{"jenkins", "CVE-2024-23897", 9.8, "CRITICAL", "Arbitrary file read via CLI args parser — RCE (< 2.442 LTS)", v("2.0"), v("2.441")},
	{"jenkins", "CVE-2024-23898", 8.8, "HIGH", "WebSocket CLI cross-site WebSocket hijacking (< 2.442)", v("2.0"), v("2.441")},
	{"jenkins", "CVE-2023-27898", 8.8, "HIGH", "XSS in update center via plugin metadata (< 2.394)", v("2.0"), v("2.393")},
	{"jenkins", "CVE-2023-27905", 5.4, "MEDIUM", "Stored XSS in update center notification (< 2.394)", v("2.0"), v("2.393")},
	{"jenkins", "CVE-2022-34177", 7.5, "HIGH", "Arbitrary file write via Pipeline job crafted ZIP archive (< 2.357)", v("2.0"), v("2.356")},
	{"jenkins", "CVE-2019-10320", 4.3, "MEDIUM", "Credentials plugin stores secrets in plain-text (< 2.175)", v("2.0"), v("2.174")},

	{"wordpress", "CVE-2022-21661", 7.5, "HIGH",     "SQL injection via WP_Query tax_query (< 5.8.3)", v("3.0"), v("5.8.2")},
	{"wordpress", "CVE-2021-29447", 6.5, "MEDIUM",   "XXE via crafted WAV media upload (5.6.0–5.7.1)", v("5.6"), v("5.7.1")},
	{"wordpress", "CVE-2023-2745",  5.3, "MEDIUM",   "Directory traversal in theme loading (< 6.2.1)", v("3.0"), v("6.2.0")},
	{"wordpress", "CVE-2019-8942",  8.8, "HIGH",     "RCE via malicious EXIF crop metadata (< 5.0.3)", v("3.5"), v("5.0.2")},
	{"wordpress", "CVE-2020-28032", 9.8, "CRITICAL", "PHP object injection via post meta (< 5.5.2)", v("3.0"), v("5.5.1")},

	{"drupal", "CVE-2018-7600", 9.8, "CRITICAL", "Drupalgeddon2 — RCE via form API render callbacks (< 7.58 / < 8.5.1)", v("6.0"), v("8.5.0")},
	{"drupal", "CVE-2019-6340",  9.8, "CRITICAL", "RCE via REST API HAL+JSON (< 8.6.10)", v("8.0"), v("8.6.9")},
	{"drupal", "CVE-2022-25271", 7.5, "HIGH",     "Access bypass via crafted sub-system request (< 9.3.12)", v("9.0"), v("9.3.11")},

	{"struts", "CVE-2017-5638",  10.0, "CRITICAL", "RCE via malicious Content-Type header (2.3.5–2.5.10)", v("2.3.5"), v("2.5.10")},
	{"struts", "CVE-2018-11776",  9.8, "CRITICAL", "RCE via namespace alwaysSelectFullNamespace (< 2.3.35 / < 2.5.17)", v("2.3"), v("2.5.16")},
	{"struts", "CVE-2023-50164",  9.8, "CRITICAL", "Path traversal via crafted upload parameter (< 2.5.33)", v("2.0"), v("2.5.32")},

	{"spring", "CVE-2022-22965", 9.8, "CRITICAL", "Spring4Shell — data binding RCE on JDK 9+ (< 5.3.18 / < 5.2.20)", v("5.0"), v("5.3.17")},
	{"spring", "CVE-2022-22963", 9.8, "CRITICAL", "SpEL RCE in Spring Cloud Function routing (< 3.2.3)", v("3.0"), v("3.2.2")},
	{"spring", "CVE-2018-1270",  9.8, "CRITICAL", "RCE via STOMP WebSocket messaging (< 4.3.16 / < 5.0.5)", v("4.0"), v("5.0.4")},

	{"lighttpd", "CVE-2022-22707", 7.0, "HIGH",   "Race condition in mod_extforward signal handling (< 1.4.64)", v("1.4"), v("1.4.63")},
	{"lighttpd", "CVE-2014-2323",  7.5, "HIGH",   "SQL injection in mod_mysql_vhost (< 1.4.34)", v("1.3"), v("1.4.33")},

	{"grafana", "CVE-2021-43798", 7.5, "HIGH",     "Directory traversal via plugin datasource URL (< 8.3.0)", v("8.0"), v("8.2.7")},
	{"grafana", "CVE-2021-41174", 6.1, "MEDIUM",   "XSS via Angular rendering in dashboards (< 8.2.3)", v("8.0"), v("8.2.2")},
	{"grafana", "CVE-2023-3128",  9.4, "CRITICAL", "Auth bypass via Azure AD email claim (< 10.0.7 / < 9.5.11)", v("6.0"), v("9.5.10")},
	{"grafana", "CVE-2022-31107", 8.0, "HIGH",     "Privilege escalation via OAuth login (< 9.1.2)", v("7.0"), v("9.1.1")},

	{"elasticsearch", "CVE-2023-31419", 7.5, "HIGH",     "StackOverflow DoS via _search API (< 8.9.1)", v("8.0"), v("8.9.0")},
	{"elasticsearch", "CVE-2021-22145", 6.5, "MEDIUM",   "Info disclosure via audit logging (< 7.13.4)", v("7.0"), v("7.13.3")},
	{"elasticsearch", "CVE-2015-5377",  9.8, "CRITICAL", "Java deserialization RCE via Thrift (< 1.6.0)", v("1.0"), v("1.5.99")},

	{"postgresql", "CVE-2023-2454",  7.2, "HIGH",   "Schema variable access via security-definer functions (< 15.3)", v("14.0"), v("15.2")},
	{"postgresql", "CVE-2022-1552",  8.8, "HIGH",   "Autovacuum executes arbitrary SQL as superuser (< 14.3)", v("10.0"), v("14.2")},
	{"postgresql", "CVE-2019-10164", 8.8, "HIGH",   "Stack overflow via SCRAM authentication (< 11.3 / < 10.8)", v("10.0"), v("11.2")},

	{"mongodb", "CVE-2019-2389", 7.5, "HIGH", "Info disclosure via $lookup aggregation (< 4.0.12/4.2.3)", v("3.0"), v("4.2.2")},
	{"mongodb", "CVE-2021-32036", 6.5, "MEDIUM", "DoS via malformed BSON packet (< 5.0.4)", v("4.0"), v("5.0.3")},
	{"mongodb", "CVE-2021-20328", 6.8, "MEDIUM", "Client-side field-level encryption key exposure (< 4.7)", v("4.0"), v("4.6.99")},
	{"mongodb", "CVE-2022-24882", 7.5, "HIGH",   "Improper signature validation in SASL (< 5.0.6)", v("4.0"), v("5.0.5")},

	{"confluence", "CVE-2023-22518",  9.1, "CRITICAL", "Improper authorization — data destruction RCE (< 8.6.1)", v("1.3"), v("8.6.0")},
	{"confluence", "CVE-2022-26134",  9.8, "CRITICAL", "OGNL injection — unauthenticated RCE (< 7.4.17/7.18.1)", v("1.3"), v("7.18.0")},
	{"confluence", "CVE-2021-26084",  9.8, "CRITICAL", "OGNL injection in page title — RCE without auth (< 7.13.0)", v("1.3"), v("7.12.5")},
	{"confluence", "CVE-2019-3396",   9.8, "CRITICAL", "Path traversal via Widget Connector macro (< 6.14.2)", v("1.0"), v("6.14.1")},

	{"jira", "CVE-2022-0540",  9.8, "CRITICAL", "Auth bypass in Seraph — unauthenticated REST/WebWork access (< 8.13.18/8.20.6)", v("7.0"), v("8.20.5")},
	{"jira", "CVE-2021-26086", 5.3, "MEDIUM",   "Path traversal — read /WEB-INF files without auth (< 8.13.6)", v("6.0"), v("8.13.5")},
	{"jira", "CVE-2019-8442",  5.3, "MEDIUM",   "Reflected XSS via ViewUserHover.jspa endpoint (< 8.4.0)", v("7.0"), v("8.3.4")},

	{"solr", "CVE-2023-50386",  8.8, "HIGH",     "Backup/restore API allows arbitrary code execution (< 9.4.1)", v("6.0"), v("9.4.0")},
	{"solr", "CVE-2021-27905",  9.8, "CRITICAL", "SSRF via Replication handler — blind RCE (< 8.8.2)", v("5.0"), v("8.8.1")},
	{"solr", "CVE-2019-17558",  9.8, "CRITICAL", "Velocity template injection RCE — Params Resource Loader (5.0–8.3.1)", v("5.0"), v("8.3.1")},
	{"solr", "CVE-2017-12629",  9.8, "CRITICAL", "XXE + SSRF chain — RCE via RunExecutableListener (< 7.1.0)", v("1.0"), v("7.0.1")},

	{"bigip", "CVE-2023-46747", 9.8, "CRITICAL", "Auth bypass in Configuration Utility — unauthenticated RCE (< 14.1.5.3)", v("13.1"), v("17.1.0")},
	{"bigip", "CVE-2022-1388",  9.8, "CRITICAL", "iControl REST API auth bypass — full device takeover (< 13.1.5/17.0.0.2)", v("13.1"), v("17.0.0")},
	{"bigip", "CVE-2021-22986", 9.8, "CRITICAL", "iControl REST unauthenticated RCE (< 12.1.6/16.0.1.1)", v("12.0"), v("16.0.1")},
	{"bigip", "CVE-2020-5902",  9.8, "CRITICAL", "RCE in TMUI — no authentication required (< 15.1.0.4)", v("11.6"), v("15.1.0")},

	{"citrix", "CVE-2023-3519",  9.8, "CRITICAL", "Citrix Bleed — unauthenticated RCE in NetScaler ADC/Gateway (< 13.1-49.13)", v("12.0"), v("13.1.49")},
	{"citrix", "CVE-2019-19781", 9.8, "CRITICAL", "Path traversal via /vpns/ — unauthenticated RCE (< 12.1-55.18)", v("11.1"), v("12.1.55")},
	{"citrix", "CVE-2023-24488", 6.1, "MEDIUM",   "Reflected XSS in Citrix ADC/Gateway login page (< 13.0-90.11)", v("12.0"), v("13.0.90")},

	{"log4j", "CVE-2021-44228", 10.0, "CRITICAL", "Log4Shell — JNDI injection RCE via log messages (2.0-beta9–2.14.1)", v("2.0"), v("2.14.1")},
	{"log4j", "CVE-2021-45046",  9.0, "CRITICAL", "Log4Shell bypass via thread context lookup patterns (2.15.0)", v("2.15"), v("2.15.0")},
	{"log4j", "CVE-2021-45105",  7.5, "HIGH",     "Infinite recursion DoS via self-referential lookups (2.0–2.16.0)", v("2.0"), v("2.16.0")},
	{"log4j", "CVE-2021-44832",  6.6, "MEDIUM",   "RCE via attacker-controlled config using JDBC Appender (< 2.17.1)", v("2.0"), v("2.17.0")},

	{"vmware", "CVE-2021-22005", 9.8, "CRITICAL", "Arbitrary file upload RCE via Analytics Service (< 7.0 U2d)", v("6.5"), v("7.0.2")},
	{"vmware", "CVE-2021-21985", 9.8, "CRITICAL", "RCE via vSAN Health Check plugin — no auth (< 7.0 U1c)", v("6.5"), v("7.0.1")},
	{"vmware", "CVE-2021-22019", 7.5, "HIGH",     "DoS via VAMI service (< 7.0 U2d)", v("6.5"), v("7.0.2")},

	{"coldfusion", "CVE-2023-38203", 9.8, "CRITICAL", "Deserialization RCE via crafted data (< 2021 Update 7)", v("2018.0"), v("2021.6")},
	{"coldfusion", "CVE-2023-29300", 9.8, "CRITICAL", "Deserialization RCE — unauthenticated (< 2021 Update 6)", v("2018.0"), v("2021.5")},
	{"coldfusion", "CVE-2023-26360", 8.6, "HIGH",     "Arbitrary file read via improper access control (< 2021 Update 6)", v("2018.0"), v("2021.5")},

	{"activemq", "CVE-2023-46604", 10.0, "CRITICAL", "ClassInfo deserialization — unauthenticated RCE via OpenWire protocol (< 5.15.16/5.16.7/5.17.6/5.18.3)", v("5.0"), v("5.18.2")},
	{"activemq", "CVE-2016-3088",   9.8, "CRITICAL", "HTTP PUT to fileserver — arbitrary file write and RCE (< 5.14.0)", v("5.0"), v("5.13.99")},
	{"activemq", "CVE-2022-41678",  8.8, "HIGH",     "Authenticated RCE via Jolokia + ClassPathXmlApplicationContext (< 5.17.6)", v("5.0"), v("5.17.5")},

	{"weblogic", "CVE-2023-21839",  7.5, "HIGH",     "Unauthenticated JNDI lookup RCE via T3/IIOP (< 14.1.1.0.0)", v("10.3"), v("14.1.0")},
	{"weblogic", "CVE-2020-14882",  9.8, "CRITICAL", "Unauthenticated RCE via /console/css/ path bypass (< 12.2.1.4.0)", v("10.3"), v("12.2.1.3")},
	{"weblogic", "CVE-2020-14883",  7.2, "HIGH",     "RCE via console component post-auth (< 12.2.1.4.0)", v("10.3"), v("12.2.1.3")},
	{"weblogic", "CVE-2019-2725",   9.8, "CRITICAL", "Deserialization RCE via _async handler — no auth (10.3.6/12.1.3)", v("10.3"), v("12.1.3")},
	{"weblogic", "CVE-2021-2394",   9.8, "CRITICAL", "Deserialization RCE via T3/IIOP (< 12.2.1.4.0)", v("10.3"), v("12.2.1.3")},

	{"exchange", "CVE-2021-26855",  9.8, "CRITICAL", "ProxyLogon — SSRF bypass auth to RCE (Exchange 2010-2019)", v("14.0"), v("15.2.99")},
	{"exchange", "CVE-2021-34473",  9.8, "CRITICAL", "ProxyShell — RCE via ACL bypass + arbitrary file write", v("14.0"), v("15.2.99")},
	{"exchange", "CVE-2022-41040",  8.8, "HIGH",     "SSRF leading to remote code execution — ProxyNotShell", v("14.0"), v("15.2.99")},
	{"exchange", "CVE-2022-41082",  8.8, "HIGH",     "RCE via PowerShell deserialization — ProxyNotShell chain", v("14.0"), v("15.2.99")},

	{"gitlab", "CVE-2023-2825",  10.0, "CRITICAL", "Path traversal — unauthenticated arbitrary file read (16.0.0)", v("16.0"), v("16.0.0")},
	{"gitlab", "CVE-2021-22205", 10.0, "CRITICAL", "RCE via ExifTool image upload — no auth on some configs (< 13.10.3)", v("11.9"), v("13.10.2")},
	{"gitlab", "CVE-2022-2185",   9.9, "CRITICAL", "RCE via project import — authenticated (< 15.1.0)", v("14.0"), v("15.0.99")},
	{"gitlab", "CVE-2023-7028",  10.0, "CRITICAL", "Account takeover via password reset email delivery flaw (< 16.7.2)", v("16.1"), v("16.7.1")},
	{"gitlab", "CVE-2021-4191",   5.3, "MEDIUM",   "Unauthenticated user enumeration via GraphQL API (< 14.8.2)", v("13.0"), v("14.8.1")},

	{"nexus", "CVE-2019-7238",  9.8, "CRITICAL", "RCE via OrientDB console — unauthenticated (< 3.15.0)", v("3.0"), v("3.14.99")},
	{"nexus", "CVE-2020-10199", 9.8, "CRITICAL", "RCE via Groovy script execution — EL injection (< 3.21.2)", v("3.0"), v("3.21.1")},
	{"nexus", "CVE-2020-10204", 9.8, "CRITICAL", "RCE via expression language injection in admin console (< 3.21.2)", v("3.0"), v("3.21.1")},

	{"zimbra", "CVE-2022-37042",  9.8, "CRITICAL", "Auth bypass leading to RCE via ProxyServlet (< 8.8.15 p33/9.0.0 p26)", v("8.0"), v("9.0.0")},
	{"zimbra", "CVE-2022-27925",  7.2, "HIGH",     "Arbitrary file upload via mboximport — RCE post-auth (< 8.8.15 p31)", v("8.0"), v("8.8.15")},
	{"zimbra", "CVE-2023-34192",  9.0, "CRITICAL", "Reflected XSS leading to account takeover (< 9.0.0 p27)", v("8.0"), v("9.0.0")},

	{"joomla", "CVE-2023-23752",  5.3, "MEDIUM",   "Unauthenticated info disclosure via /api/index.php/v1/config (< 4.2.8)", v("4.0"), v("4.2.7")},
	{"joomla", "CVE-2015-8562",   9.8, "CRITICAL", "PHP object injection via crafted User-Agent — unauthenticated RCE (< 3.4.6)", v("1.5"), v("3.4.5")},
	{"joomla", "CVE-2017-8917",   9.8, "CRITICAL", "SQL injection in com_fields (< 3.7.1)", v("3.7"), v("3.7.0")},

	{"magento", "CVE-2022-24086",  9.8, "CRITICAL", "Improper input validation — unauthenticated RCE (< 2.3.7-p3/2.4.3-p2)", v("2.3"), v("2.4.3")},
	{"magento", "CVE-2021-21024",  7.7, "HIGH",     "SQL injection in order processing (< 2.4.2)", v("2.0"), v("2.4.1")},
	{"magento", "CVE-2019-8144",   9.8, "CRITICAL", "Remote code execution via Page Builder component (2.3.x < 2.3.3)", v("2.3"), v("2.3.2")},

	{"roundcube", "CVE-2023-43770",  6.1, "MEDIUM",  "Cross-site scripting via SVG in email attachments (< 1.4.14/1.5.4/1.6.3)", v("1.4"), v("1.6.2")},
	{"roundcube", "CVE-2020-35730",  6.1, "MEDIUM",  "Stored XSS via HTML email with dangerous CSS property (< 1.4.10/1.3.15)", v("1.2"), v("1.4.9")},
	{"roundcube", "CVE-2023-5631",   5.4, "MEDIUM",  "Stored XSS via HTML email SVG — persistent (< 1.6.4)", v("1.4"), v("1.6.3")},

	{"keycloak", "CVE-2023-2585",  8.0, "HIGH",   "Open redirect and SSRF via request_uri parameter (< 21.0.2)", v("18.0"), v("21.0.1")},
	{"keycloak", "CVE-2023-0091",  6.1, "MEDIUM",  "Reflected XSS in SAML/OIDC error handling (< 20.0.5)", v("18.0"), v("20.0.4")},
	{"keycloak", "CVE-2021-3827",  6.8, "MEDIUM",  "Auth bypass via empty grant_type in device auth flow (< 15.1.0)", v("14.0"), v("15.0.99")},

	{"fortinet", "CVE-2023-27997",  9.8, "CRITICAL", "Heap buffer overflow in SSL-VPN — pre-auth RCE (< 6.0.17/6.2.15/6.4.13/7.0.12/7.2.5)", v("6.0"), v("7.2.4")},
	{"fortinet", "CVE-2022-42475",  9.3, "CRITICAL", "Heap overflow in SSL-VPN — RCE without authentication (< 7.2.3)", v("6.0"), v("7.2.2")},
	{"fortinet", "CVE-2022-40684",  9.8, "CRITICAL", "Auth bypass via crafted HTTP/HTTPS requests — full admin access", v("7.0"), v("7.2.1")},

	{"pulse", "CVE-2021-22893", 10.0, "CRITICAL", "Pre-auth RCE via unspecified vectors in Pulse Connect Secure (< 9.1R11.4)", v("9.0"), v("9.1.11")},
	{"pulse", "CVE-2023-46805",  8.2, "HIGH",     "Auth bypass in Ivanti ICS via X-Forwarded-For (9.x / 22.x)", v("9.0"), v("22.6.99")},
	{"pulse", "CVE-2021-22937",  9.1, "CRITICAL", "Config file manipulation — RCE (< 9.1R12)", v("9.0"), v("9.1.11")},

	{"harbor", "CVE-2022-31671",  9.9, "CRITICAL", "SSRF + privilege escalation via webhook endpoint (< 2.5.2/2.4.4)", v("2.0"), v("2.5.1")},
	{"harbor", "CVE-2022-31670",  8.8, "HIGH",     "Auth bypass via forged JWT token (< 2.5.2/2.4.4)", v("2.0"), v("2.5.1")},

	{"memcached", "CVE-2018-1000115", 7.5, "HIGH",  "No authentication — full cache read/write over UDP (all versions)", v("1.0"), v("1.99.99")},
	{"memcached", "CVE-2011-4971",    6.5, "MEDIUM", "NULL pointer dereference via crafted binary packet (< 1.4.13)", v("1.0"), v("1.4.12")},

	{"zookeeper", "CVE-2023-44981",  9.1, "CRITICAL", "Auth bypass via SASL Quorum Peer Authentication (< 3.7.2/3.8.3/3.9.1)", v("3.4"), v("3.9.0")},
	{"zookeeper", "CVE-2019-0201",   5.9, "MEDIUM",   "Info disclosure via getACL without auth (< 3.4.14/3.5.5)", v("3.4"), v("3.5.4")},

	{"kubernetes", "CVE-2018-1002105", 9.8, "CRITICAL", "Privilege escalation via aggregated API servers (< 1.10.11/1.11.5/1.12.3)", v("1.0"), v("1.12.2")},
	{"kubernetes", "CVE-2022-3294",    8.8, "HIGH",     "Node address auth bypass leading to SSRF (< 1.23.13/1.24.7/1.25.3)", v("1.23"), v("1.25.2")},

	{"openssl", "CVE-2014-0160",  7.5, "HIGH",     "Heartbleed — memory disclosure via TLS heartbeat (1.0.1-1.0.1f)", v("1.0.1"), v("1.0.1")},
	{"openssl", "CVE-2022-0778",  7.5, "HIGH",     "Infinite loop in BN_mod_sqrt() — DoS via crafted cert (< 1.0.2zd/1.1.1n/3.0.2)", v("1.0.1"), v("3.0.1")},
	{"openssl", "CVE-2022-3786",  7.5, "HIGH",     "Punycode buffer overflow in X.509 cert verification (3.0.0-3.0.6)", v("3.0.0"), v("3.0.6")},

	{"jboss", "CVE-2017-12149",   9.8, "CRITICAL", "RCE via Java deserialization in JMXINVOKERSERVLET (< EAP 6.4.17)", v("4.0"), v("6.4.16")},
	{"jboss", "CVE-2015-7501",    9.8, "CRITICAL", "Java deserialization RCE via JMX InvokerServlet", v("4.0"), v("6.4.3")},
}

func buildMatches(host string, port int, rawBanner string, detections []detected) []Match {
	seenCVE := make(map[string]bool)
	var matches []Match
	for _, e := range db {
		for _, d := range detections {
			if d.product != e.product {
				continue
			}
			// Presence-only detection fires all CVEs for the product.
			// Version-matched detection requires the version to be in range.
			if !d.presenceOnly && !inRange(e, d) {
				continue
			}
			if seenCVE[e.cve] {
				continue
			}
			seenCVE[e.cve] = true
			matches = append(matches, Match{
				Host:        host,
				Port:        port,
				Banner:      rawBanner,
				CVE:         e.cve,
				CVSS:        e.cvss,
				Severity:    e.severity,
				Description: e.desc,
				Link:        nvdBase + e.cve,
			})
		}
	}
	return matches
}

// CheckBanner checks a raw TCP service banner (e.g. SSH, FTP, SMTP) against
// the embedded CVE database using version-range comparison.
func CheckBanner(host string, port int, banner string) []Match {
	return buildMatches(host, port, banner, fromBanner(banner))
}

// CheckHTTPFull checks HTTP response headers AND body against the CVE database.
func CheckHTTPFull(host string, port int, h http.Header, body string) []Match {
	if h == nil {
		return nil
	}
	server := strings.TrimSpace(h.Get("Server") + " " + h.Get("X-Powered-By"))
	detections := fromHeaders(h)
	detections = append(detections, fromBody(body)...)
	return buildMatches(host, port, server, detections)
}

// CheckHTTP checks only HTTP response headers (legacy — prefer CheckHTTPFull).
func CheckHTTP(host string, port int, h http.Header) []Match {
	return CheckHTTPFull(host, port, h, "")
}
