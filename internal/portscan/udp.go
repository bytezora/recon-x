package portscan

import (
	"fmt"
	"net"
	"time"
)

type UDPResult struct {
	Host    string
	Port    int
	State   string
	Service string
}

var commonUDPPorts = []int{
	53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520,
	1194, 1812, 1813, 4500, 5353, 5060,
}

var udpProbes = map[int][]byte{
	53:   {0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03},
	123:  {0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	161:  {0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa1, 0x19, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00},
	5353: {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, '_', 'h', 't', 't', 'p', 0x04, '_', 't', 'c', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c, 0x00, 0x01},
}

var udpServiceNames = map[int]string{
	53:   "dns",
	67:   "dhcp",
	68:   "dhcp-client",
	69:   "tftp",
	123:  "ntp",
	137:  "netbios-ns",
	138:  "netbios-dgm",
	161:  "snmp",
	162:  "snmp-trap",
	500:  "isakmp",
	514:  "syslog",
	520:  "rip",
	1194: "openvpn",
	1812: "radius",
	1813: "radius-acct",
	4500: "ipsec",
	5353: "mdns",
	5060: "sip",
}

func ScanUDP(host string, onFound func(UDPResult)) []UDPResult {
	var results []UDPResult
	for _, port := range commonUDPPorts {
		r := probeUDP(host, port)
		if r != nil {
			results = append(results, *r)
			if onFound != nil {
				onFound(*r)
			}
		}
	}
	return results
}

func probeUDP(host string, port int) *UDPResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	probe, ok := udpProbes[port]
	if ok {
		conn.Write(probe)
	} else {
		conn.Write([]byte{0x00})
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	if n > 0 {
		svc := udpServiceNames[port]
		return &UDPResult{
			Host:    host,
			Port:    port,
			State:   "open",
			Service: svc,
		}
	}
	return nil
}
