package portscan

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type OSHint struct {
	Host    string
	OSGuess string
	TTL     int
	Basis   string
}

func GuessOS(host string, openPorts []int) OSHint {
	hint := OSHint{Host: host}

	ttl := probeTTL(host, openPorts)
	hint.TTL = ttl

	switch {
	case ttl >= 120 && ttl <= 128:
		hint.OSGuess = "Windows"
		hint.Basis = fmt.Sprintf("TTL=%d (typical Windows 128)", ttl)
	case ttl >= 60 && ttl <= 64:
		hint.OSGuess = "Linux/Unix"
		hint.Basis = fmt.Sprintf("TTL=%d (typical Linux 64)", ttl)
	case ttl >= 250 && ttl <= 255:
		hint.OSGuess = "Cisco/Network device"
		hint.Basis = fmt.Sprintf("TTL=%d (typical Cisco 255)", ttl)
	case ttl >= 250:
		hint.OSGuess = "Solaris/AIX"
		hint.Basis = fmt.Sprintf("TTL=%d (typical Solaris/AIX 255)", ttl)
	default:
		hint.OSGuess = "Unknown"
		hint.Basis = fmt.Sprintf("TTL=%d", ttl)
	}

	portHint := guessOSFromPorts(openPorts)
	if portHint != "" {
		if hint.OSGuess == "Unknown" {
			hint.OSGuess = portHint
		} else {
			hint.OSGuess = hint.OSGuess + " (" + portHint + ")"
		}
		hint.Basis += "; open ports: " + portHint
	}

	return hint
}

func probeTTL(host string, openPorts []int) int {
	port := 80
	if len(openPorts) > 0 {
		port = openPorts[0]
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		return 0
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()
	_ = localAddr
	return 0
}

func guessOSFromPorts(ports []int) string {
	hasRDP := false
	hasWinRM := false
	hasSMB := false
	hasLinuxSrv := false

	for _, p := range ports {
		switch p {
		case 3389:
			hasRDP = true
		case 5985, 5986:
			hasWinRM = true
		case 445, 139:
			hasSMB = true
		case 22:
			hasLinuxSrv = true
		}
	}

	if hasRDP || hasWinRM {
		return "likely Windows Server"
	}
	if hasSMB && !hasLinuxSrv {
		return "likely Windows"
	}
	if hasLinuxSrv && !hasRDP {
		return "likely Linux"
	}
	return ""
}

func BannerOSHint(banners []string) string {
	for _, b := range banners {
		lower := strings.ToLower(b)
		switch {
		case strings.Contains(lower, "ubuntu"):
			return "Ubuntu Linux"
		case strings.Contains(lower, "debian"):
			return "Debian Linux"
		case strings.Contains(lower, "centos"):
			return "CentOS Linux"
		case strings.Contains(lower, "windows"):
			return "Windows"
		case strings.Contains(lower, "freebsd"):
			return "FreeBSD"
		case strings.Contains(lower, "cisco"):
			return "Cisco IOS"
		case strings.Contains(lower, "openssh"):
			return "Linux/Unix (OpenSSH)"
		}
	}
	return ""
}
