package nmapxml

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bytezora/recon-x/internal/portscan"
	"github.com/bytezora/recon-x/internal/vulns"
)

type ImportResult struct {
	Ports        []portscan.Result
	Fingerprints []vulns.Fingerprint
}

type run struct {
	Hosts []host `xml:"host"`
}

type host struct {
	Status    status     `xml:"status"`
	Addresses []address  `xml:"address"`
	Hostnames []hostname `xml:"hostnames>hostname"`
	Ports     []port     `xml:"ports>port"`
}

type status struct {
	State string `xml:"state,attr"`
}

type address struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    state   `xml:"state"`
	Service  service `xml:"service"`
}

type state struct {
	State string `xml:"state,attr"`
}

type service struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr"`
	Version   string   `xml:"version,attr"`
	ExtraInfo string   `xml:"extrainfo,attr"`
	Tunnel    string   `xml:"tunnel,attr"`
	CPEs      []string `xml:"cpe"`
}

func ParseFile(path string) (ImportResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return ImportResult{}, err
	}
	defer f.Close()

	var parsed run
	if err := xml.NewDecoder(f).Decode(&parsed); err != nil {
		return ImportResult{}, err
	}
	return fromRun(parsed), nil
}

func fromRun(parsed run) ImportResult {
	var out ImportResult
	seenPorts := make(map[string]bool)
	seenFP := make(map[string]bool)
	for _, h := range parsed.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		hostName := bestHost(h)
		ip := bestIP(h)
		if hostName == "" {
			hostName = ip
		}
		for _, p := range h.Ports {
			if p.State.State != "open" || p.Protocol != "tcp" {
				continue
			}
			portNum, err := strconv.Atoi(p.PortID)
			if err != nil || portNum <= 0 {
				continue
			}
			banner := bannerFor(p.Service)
			key := hostName + "|" + strconv.Itoa(portNum)
			if !seenPorts[key] {
				seenPorts[key] = true
				out.Ports = append(out.Ports, portscan.Result{
					Host:    hostName,
					Port:    portNum,
					IP:      ip,
					Banner:  banner,
					Service: p.Service.Name,
					State:   "open",
				})
			}
			fp := fingerprintFor(hostName, portNum, banner, p.Service)
			if fp.Product == "" {
				continue
			}
			fpKey := hostName + "|" + strconv.Itoa(portNum) + "|" + fp.Product + "|" + fp.Version + "|" + fp.CPE
			if seenFP[fpKey] {
				continue
			}
			seenFP[fpKey] = true
			out.Fingerprints = append(out.Fingerprints, fp)
		}
	}
	return out
}

func bestHost(h host) string {
	for _, hn := range h.Hostnames {
		if hn.Name != "" {
			return hn.Name
		}
	}
	return ""
}

func bestIP(h host) string {
	for _, addr := range h.Addresses {
		if addr.Type == "ipv4" || addr.Type == "ipv6" {
			return addr.Addr
		}
	}
	if len(h.Addresses) > 0 {
		return h.Addresses[0].Addr
	}
	return ""
}

func bannerFor(s service) string {
	parts := []string{s.Name}
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	if s.ExtraInfo != "" {
		parts = append(parts, s.ExtraInfo)
	}
	for _, cpe := range s.CPEs {
		if cpe != "" {
			parts = append(parts, cpe)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func fingerprintFor(host string, port int, evidence string, s service) vulns.Fingerprint {
	product := normalizeProduct(s.Product, s.Name, s.CPEs)
	version := strings.TrimSpace(s.Version)
	cpe := normalizeNmapCPE(firstCPE(s.CPEs))
	conf := "version"
	if version == "" {
		conf = "product"
	}
	if product == "" && cpe != "" {
		product = productFromCPE(cpe)
	}
	return vulns.Fingerprint{
		Host:       host,
		Port:       port,
		Product:    product,
		Version:    version,
		CPE:        cpe,
		VirtualCPE: virtualCPE(cpe),
		Evidence:   evidence,
		Source:     "nmap-xml",
		Confidence: conf,
	}
}

func normalizeProduct(product, name string, cpes []string) string {
	raw := strings.ToLower(strings.TrimSpace(product))
	if raw == "" {
		raw = strings.ToLower(strings.TrimSpace(name))
	}
	replacer := strings.NewReplacer(" ", "", "-", "", "_", "")
	key := replacer.Replace(raw)
	switch {
	case strings.Contains(key, "apachehttpd") || key == "apache" || key == "httpd":
		return "apache"
	case strings.Contains(key, "openssh"):
		return "openssh"
	case strings.Contains(key, "nginx"):
		return "nginx"
	case strings.Contains(key, "microsoftiis"):
		return "iis"
	case strings.Contains(key, "tomcat"):
		return "tomcat"
	case strings.Contains(key, "wordpress"):
		return "wordpress"
	case strings.Contains(key, "jenkins"):
		return "jenkins"
	case strings.Contains(key, "gitlab"):
		return "gitlab"
	case strings.Contains(key, "confluence"):
		return "confluence"
	case strings.Contains(key, "jira"):
		return "jira"
	case strings.Contains(key, "grafana"):
		return "grafana"
	case strings.Contains(key, "elasticsearch"):
		return "elasticsearch"
	case strings.Contains(key, "redis"):
		return "redis"
	case strings.Contains(key, "mysql"):
		return "mysql"
	case strings.Contains(key, "postgres"):
		return "postgresql"
	case strings.Contains(key, "mongodb"):
		return "mongodb"
	case strings.Contains(key, "openss"):
		return "openssl"
	}
	for _, cpe := range cpes {
		if p := productFromCPE(cpe); p != "" {
			return p
		}
	}
	return raw
}

func firstCPE(cpes []string) string {
	for _, cpe := range cpes {
		cpe = strings.TrimSpace(cpe)
		if cpe != "" {
			return cpe
		}
	}
	return ""
}

func productFromCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	product := strings.TrimSpace(parts[4])
	switch product {
	case "http_server":
		return "apache"
	case "internet_information_services":
		return "iis"
	case "httpd":
		return "apache"
	}
	return strings.ReplaceAll(product, "\\!", "!")
}

func virtualCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s", parts[0], parts[1], parts[2], parts[3], parts[4])
}

func normalizeNmapCPE(cpe string) string {
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
