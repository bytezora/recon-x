package axfr

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

type Result struct {
	NS      string   `json:"ns"`
	Success bool     `json:"success"`
	Records []Record `json:"records"`
	Err     string   `json:"error,omitempty"`
}

func Transfer(domain string) []Result {
	nss, err := net.LookupNS(domain)
	if err != nil || len(nss) == 0 {
		return []Result{{NS: "(none)", Err: fmt.Sprintf("NS lookup failed: %v", err)}}
	}

	var out []Result
	for _, ns := range nss {
		r := tryAXFR(domain, strings.TrimSuffix(ns.Host, "."))
		out = append(out, r)
	}
	return out
}

func tryAXFR(domain, ns string) Result {
	addr := net.JoinHostPort(ns, "53")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return Result{NS: ns, Err: err.Error()}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck

	msg := buildQuery(domain, 252) // QTYPE AXFR = 252
	if err := sendMsg(conn, msg); err != nil {
		return Result{NS: ns, Err: err.Error()}
	}

	var records []Record
	soaCount := 0
	for {
		data, err := recvMsg(conn)
		if err != nil {
			break
		}
		recs, soa, err := parseResponse(data)
		if err != nil {
			break
		}
		soaCount += soa
		records = append(records, recs...)
		if soaCount >= 2 && len(records) > 0 {
			break
		}
	}

	if len(records) == 0 {
		return Result{NS: ns, Err: "AXFR refused or empty"}
	}
	return Result{NS: ns, Success: true, Records: records}
}

func sendMsg(conn net.Conn, msg []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	_, err := conn.Write(append(hdr[:], msg...))
	return err
}

func recvMsg(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint16(hdr[:])
	if l == 0 {
		return nil, fmt.Errorf("zero-length message")
	}
	data := make([]byte, l)
	_, err := io.ReadFull(conn, data)
	return data, err
}

func buildQuery(domain string, qtype uint16) []byte {
	var msg []byte
	msg = append(msg, 0xAB, 0xCD) // random ID
	msg = append(msg, 0x00, 0x00) // flags: standard query
	msg = append(msg, 0x00, 0x01) // QDCOUNT: 1
	msg = append(msg, 0x00, 0x00) // ANCOUNT: 0
	msg = append(msg, 0x00, 0x00) // NSCOUNT: 0
	msg = append(msg, 0x00, 0x00) // ARCOUNT: 0
	msg = append(msg, encodeName(domain)...)
	msg = append(msg, byte(qtype>>8), byte(qtype))
	msg = append(msg, 0x00, 0x01) // QCLASS: IN
	return msg
}

func encodeName(name string) []byte {
	var buf []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	return buf
}

// parseName reads a DNS name from data at offset, following compression pointers.
func parseName(data []byte, offset int) (string, int) {
	var labels []string
	origOffset := -1
	visited := make(map[int]bool)

	for {
		if offset >= len(data) {
			break
		}
		if visited[offset] {
			break
		}
		visited[offset] = true

		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			ptr := (int(length&0x3F) << 8) | int(data[offset+1])
			if origOffset == -1 {
				origOffset = offset + 2
			}
			offset = ptr
			continue
		}
		offset++
		end := offset + length
		if end > len(data) {
			break
		}
		labels = append(labels, string(data[offset:end]))
		offset = end
	}

	if origOffset != -1 {
		return strings.Join(labels, "."), origOffset
	}
	return strings.Join(labels, "."), offset
}

func rrTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func parseRData(data []byte, offset, length int, rrtype uint16) string {
	end := offset + length
	if end > len(data) {
		return "(truncated)"
	}
	rdata := data[offset:end]

	switch rrtype {
	case 1: // A
		if len(rdata) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			parts := make([]string, 8)
			for i := range parts {
				parts[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(rdata[i*2:]))
			}
			return strings.Join(parts, ":")
		}
	case 2, 5, 12: // NS, CNAME, PTR
		name, _ := parseName(data, offset)
		return name
	case 15: // MX
		if len(rdata) >= 3 {
			pref := binary.BigEndian.Uint16(rdata[:2])
			name, _ := parseName(data, offset+2)
			return fmt.Sprintf("%d %s", pref, name)
		}
	case 16: // TXT
		var parts []string
		i := 0
		for i < len(rdata) {
			l := int(rdata[i])
			i++
			if i+l > len(rdata) {
				break
			}
			parts = append(parts, string(rdata[i:i+l]))
			i += l
		}
		return strings.Join(parts, "")
	case 6: // SOA
		mname, off := parseName(data, offset)
		rname, _ := parseName(data, off)
		return mname + " " + rname
	case 33: // SRV
		if len(rdata) >= 7 {
			prio := binary.BigEndian.Uint16(rdata[:2])
			weight := binary.BigEndian.Uint16(rdata[2:4])
			port := binary.BigEndian.Uint16(rdata[4:6])
			target, _ := parseName(data, offset+6)
			return fmt.Sprintf("%d %d %d %s", prio, weight, port, target)
		}
	}
	return fmt.Sprintf("(raw %d bytes)", length)
}

func parseResponse(data []byte) ([]Record, int, error) {
	if len(data) < 12 {
		return nil, 0, fmt.Errorf("message too short (%d bytes)", len(data))
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	rcode := flags & 0x000F
	if rcode != 0 {
		return nil, 0, fmt.Errorf("DNS RCODE %d (REFUSED/NOTAUTH/etc.)", rcode)
	}

	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))
	offset := 12

	// skip questions
	for i := 0; i < qdCount && offset < len(data); i++ {
		_, offset = parseName(data, offset)
		offset += 4 // QTYPE + QCLASS
	}

	var records []Record
	soaCount := 0

	for i := 0; i < anCount && offset < len(data); i++ {
		name, newOffset := parseName(data, offset)
		offset = newOffset
		if offset+10 > len(data) {
			break
		}

		rrtype := binary.BigEndian.Uint16(data[offset : offset+2])
		ttl    := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdlen  := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10

		value := parseRData(data, offset, rdlen, rrtype)
		offset += rdlen

		if rrtype == 6 {
			soaCount++
		}

		records = append(records, Record{
			Name:  name,
			Type:  rrTypeName(rrtype),
			TTL:   ttl,
			Value: value,
		})
	}

	return records, soaCount, nil
}
