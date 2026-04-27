package whois

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type Result struct {
	Target    string   `json:"target"`
	Registrar string   `json:"registrar,omitempty"`
	Org       string   `json:"org,omitempty"`
	Country   string   `json:"country,omitempty"`
	Created   string   `json:"created,omitempty"`
	Updated   string   `json:"updated,omitempty"`
	Expires   string   `json:"expires,omitempty"`
	NameSrvs  []string `json:"name_servers,omitempty"`
}

func Lookup(domain string) (*Result, error) {
	raw, err := query("whois.iana.org", domain)
	if err != nil {
		return nil, fmt.Errorf("whois.iana.org: %w", err)
	}

	referral := fieldValue(raw, "refer")
	if referral != "" && referral != "whois.iana.org" {
		if raw2, err := query(referral, domain); err == nil {
			raw = raw2
		}
	}

	r := &Result{Target: domain}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		if val == "" {
			continue
		}
		switch {
		case key == "registrar" && r.Registrar == "":
			r.Registrar = val
		case (key == "registrant organization" || key == "org" || key == "organisation") && r.Org == "":
			r.Org = val
		case (key == "registrant country" || key == "country") && r.Country == "":
			r.Country = val
		case (key == "creation date" || key == "created" || key == "registered") && r.Created == "":
			r.Created = val
		case (key == "updated date" || key == "last-modified" || key == "changed") && r.Updated == "":
			r.Updated = val
		case (key == "registry expiry date" || key == "expiry date" || key == "expires" || key == "expiration date") && r.Expires == "":
			r.Expires = val
		case key == "name server" || key == "nserver" || key == "nameserver":
			ns := strings.ToLower(strings.Fields(val)[0])
			r.NameSrvs = append(r.NameSrvs, ns)
		}
	}

	return r, nil
}

func fieldValue(raw, field string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		kv := strings.SplitN(line, ":", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), field) {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

func query(server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", 6*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	fmt.Fprintf(conn, "%s\r\n", domain) //nolint:errcheck

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}
	return sb.String(), nil
}
