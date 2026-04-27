package banner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	dialTimeout = 3 * time.Second
	readTimeout = 3 * time.Second
	maxLen      = 120
)

func Grab(ip string, port int) string {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return GrabConn(conn, port)
}

func GrabConn(conn net.Conn, port int) string {
	conn.SetDeadline(time.Now().Add(readTimeout))

	switch port {
	case 21:
		return grabFTP(conn)
	case 22:
		return grabSSH(conn)
	case 23:
		return grabTelnet(conn)
	case 25, 465, 587:
		return grabSMTP(conn)
	case 53:
		return grabDNS(conn)
	case 110, 995:
		return grabPOP3(conn)
	case 143, 993:
		return grabIMAP(conn)
	case 389, 636, 3268:
		return grabLDAP(conn)
	case 445, 139:
		return grabSMB(conn)
	case 554:
		return grabRTSP(conn)
	case 1883, 8883:
		return grabMQTT(conn)
	case 3306:
		return grabMySQL(conn)
	case 3389:
		return grabRDP(conn)
	case 5060, 5061:
		return grabSIP(conn)
	case 5432:
		return grabPostgres(conn)
	case 5900, 5901, 5902:
		return grabVNC(conn)
	case 5985, 5986:
		return grabWinRM(conn)
	case 6379:
		return grabRedis(conn)
	case 6443, 10250, 10255:
		return grabKubernetes(conn)
	case 9200, 9300:
		return grabElasticsearch(conn)
	case 9090:
		return grabPrometheus(conn)
	case 9042:
		return grabCassandra(conn)
	case 11211:
		return grabMemcached(conn)
	case 2181:
		return grabZookeeper(conn)
	case 5601:
		return grabKibana(conn)
	case 27017, 27018, 28017:
		return grabMongoDB(conn)
	case 61616:
		return grabActiveMQ(conn)
	}

	if isHTTP(port) {
		return grabHTTP(conn)
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return ""
	}
	line := strings.TrimSpace(scanner.Text())
	if len(line) > maxLen {
		return line[:maxLen] + "…"
	}
	return line
}

func grabHTTP(conn net.Conn) string {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			val := strings.TrimSpace(line[7:])
			if len(val) > maxLen {
				return val[:maxLen] + "…"
			}
			return val
		}
	}
	return ""
}

func grabRedis(conn net.Conn) string {
	fmt.Fprintf(conn, "INFO server\r\n")
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "redis_version:") {
			ver := strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
			return "Redis server v=" + ver
		}
	}
	return ""
}

func grabMySQL(conn net.Conn) string {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return ""
	}
	payloadLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if payloadLen < 2 || payloadLen > 300 {
		return ""
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return ""
	}
	if payload[0] != 10 {
		return ""
	}
	null := bytes.IndexByte(payload[1:], 0)
	if null < 0 {
		return ""
	}
	full := string(payload[1 : 1+null])
	if dash := strings.IndexByte(full, '-'); dash > 0 {
		full = full[:dash]
	}
	return full + "-MySQL"
}

func grabMemcached(conn net.Conn) string {
	fmt.Fprintf(conn, "version\r\n")
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VERSION ") {
			ver := strings.TrimPrefix(line, "VERSION ")
			return "Memcached " + strings.TrimSpace(ver)
		}
	}
	return ""
}

func grabZookeeper(conn net.Conn) string {
	fmt.Fprintf(conn, "srvr\r\n")
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Zookeeper version:") {
			ver := strings.TrimPrefix(line, "Zookeeper version:")
			ver = strings.TrimSpace(ver)
			if idx := strings.Index(ver, "-"); idx > 0 {
				ver = ver[:idx]
			}
			if idx := strings.Index(ver, ","); idx > 0 {
				ver = ver[:idx]
			}
			return strings.TrimSpace(ver)
		}
	}
	return ""
}

func grabActiveMQ(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	for i := 0; i < 5 && scanner.Scan(); i++ {
		line := scanner.Text()
		if strings.Contains(line, "ActiveMQ") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func isHTTP(port int) bool {
	switch port {
	case 80, 81, 82, 83, 84, 85, 443, 591, 593, 832, 981, 1010, 1311, 2082,
		2087, 2095, 2096, 3000, 4000, 4001, 4002, 4567, 5000, 5001, 5104,
		5108, 5800, 7000, 7001, 7396, 7474, 8000, 8001, 8008, 8080, 8083,
		8085, 8088, 8090, 8161, 8180, 8443, 8800, 8888, 8983, 9000, 9001,
		9043, 9060, 9080, 9200, 9443, 9800, 9981, 9999, 12443, 15672, 16080:
		return true
	}
	return false
}

func grabPostgres(conn net.Conn) string {
	params := []byte("user\x00postgres\x00database\x00postgres\x00\x00")
	totalLen := 8 + len(params)
	startup := make([]byte, totalLen)
	startup[0] = byte(totalLen >> 24)
	startup[1] = byte(totalLen >> 16)
	startup[2] = byte(totalLen >> 8)
	startup[3] = byte(totalLen)
	startup[4], startup[5], startup[6], startup[7] = 0, 3, 0, 0
	copy(startup[8:], params)

	if _, err := conn.Write(startup); err != nil {
		return ""
	}

	for i := 0; i < 32; i++ {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return ""
		}
		msgType := hdr[0]
		msgLen := int(hdr[1])<<24 | int(hdr[2])<<16 | int(hdr[3])<<8 | int(hdr[4])
		bodyLen := msgLen - 4
		if bodyLen < 0 || bodyLen > 65536 {
			return ""
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(conn, body); err != nil {
				return ""
			}
		}
		switch msgType {
		case 'S':
			null := bytes.IndexByte(body, 0)
			if null < 0 {
				continue
			}
			name := string(body[:null])
			if name == "server_version" && null+1 < len(body) {
				rest := body[null+1:]
				null2 := bytes.IndexByte(rest, 0)
				if null2 < 0 {
					break
				}
				return "PostgreSQL " + string(rest[:null2])
			}
		case 'R':
			if bodyLen >= 4 {
				authType := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
				if authType != 0 {
					return ""
				}
			}
		case 'E', 'Z':
			return ""
		}
	}
	return ""
}

func grabMongoDB(conn net.Conn) string {
	bsonDoc := []byte{
		0x22, 0x00, 0x00, 0x00,
		0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x02, '$', 'd', 'b', 0x00,
		0x06, 0x00, 0x00, 0x00, 'a', 'd', 'm', 'i', 'n', 0x00,
		0x00,
	}
	msgLen := 16 + 4 + 1 + len(bsonDoc)
	le32 := func(v uint32) []byte {
		return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	}
	msg := make([]byte, 0, msgLen)
	msg = append(msg, le32(uint32(msgLen))...)
	msg = append(msg, le32(1)...)
	msg = append(msg, le32(0)...)
	msg = append(msg, le32(2013)...)
	msg = append(msg, le32(0)...)
	msg = append(msg, 0)
	msg = append(msg, bsonDoc...)

	if _, err := conn.Write(msg); err != nil {
		return ""
	}

	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return ""
	}
	respLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 | int(hdr[3])<<24
	if respLen < 21 || respLen > 65536 {
		return ""
	}
	body := make([]byte, respLen-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		return ""
	}
	if len(body) < 5 || body[4] != 0 {
		return ""
	}
	target := append([]byte{0x02}, []byte("version\x00")...)
	idx := bytes.Index(body[5:], target)
	if idx < 0 {
		return ""
	}
	after := body[5+idx+len(target):]
	if len(after) < 5 {
		return ""
	}
	strLen := int(after[0]) | int(after[1])<<8 | int(after[2])<<16 | int(after[3])<<24
	if strLen < 1 || strLen > 32 {
		return ""
	}
	return "MongoDB " + string(after[4:4+strLen-1])
}

func grabSSH(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SSH-") {
			return line
		}
	}
	return ""
}

func grabFTP(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "220") {
			if len(line) > maxLen {
				return line[:maxLen] + "…"
			}
			return line
		}
	}
	return ""
}

func grabSMTP(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "220") {
			if len(line) > maxLen {
				return line[:maxLen] + "…"
			}
			return line
		}
	}
	return ""
}

func grabPOP3(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "+OK") {
			if len(line) > maxLen {
				return line[:maxLen] + "…"
			}
			return line
		}
	}
	return ""
}

func grabIMAP(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "* OK") {
			if len(line) > maxLen {
				return line[:maxLen] + "…"
			}
			return line
		}
	}
	return ""
}

func grabVNC(conn net.Conn) string {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return ""
	}
	if strings.HasPrefix(string(buf), "RFB ") {
		return "VNC RFB " + strings.TrimSpace(string(buf[4:]))
	}
	return ""
}

func grabRDP(conn net.Conn) string {
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 19)
	n, _ := conn.Read(buf)
	if n > 4 && buf[0] == 0x03 && buf[1] == 0x00 {
		return "RDP (Microsoft Terminal Services)"
	}
	return "RDP"
}

func grabTelnet(conn net.Conn) string {
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	clean := make([]byte, 0, n)
	i := 0
	for i < n {
		if buf[i] == 0xFF && i+2 < n {
			i += 3
			continue
		}
		if buf[i] >= 0x20 && buf[i] < 0x7F {
			clean = append(clean, buf[i])
		}
		i++
	}
	result := strings.TrimSpace(string(clean))
	if result == "" {
		return "Telnet"
	}
	if len(result) > maxLen {
		return result[:maxLen] + "…"
	}
	return result
}

func grabLDAP(conn net.Conn) string {
	bindReq := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x60, 0x07,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0x80, 0x00,
	}
	if _, err := conn.Write(bindReq); err != nil {
		return ""
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 5 && buf[0] == 0x30 {
		return "LDAP service"
	}
	return ""
}

func grabDNS(conn net.Conn) string {
	query := []byte{
		0x00, 0x1d,
		0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00,
		0x00, 0x10, 0x00, 0x03,
	}
	if _, err := conn.Write(query); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 12 {
		return "DNS service"
	}
	return ""
}

func grabMQTT(conn net.Conn) string {
	connect := []byte{
		0x10, 0x16,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,
		0x02,
		0x00, 0x3c,
		0x00, 0x0a,
		'r', 'e', 'c', 'o', 'n', '-', 'x', '-', 'p', 'b',
	}
	if _, err := conn.Write(connect); err != nil {
		return ""
	}
	buf := make([]byte, 8)
	n, _ := conn.Read(buf)
	if n >= 4 && buf[0] == 0x20 {
		if buf[3] == 0x00 {
			return "MQTT broker (auth not required)"
		}
		return "MQTT broker"
	}
	return ""
}

func grabSMB(conn net.Conn) string {
	negProto := []byte{
		0x00, 0x00, 0x00, 0x2f,
		0xff, 0x53, 0x4d, 0x42,
		0x72,
		0x00, 0x00, 0x00, 0x00,
		0x18, 0x01, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xfe, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0b,
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
	}
	if _, err := conn.Write(negProto); err != nil {
		return ""
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 8 && buf[4] == 0xff && buf[5] == 0x53 && buf[6] == 0x4d && buf[7] == 0x42 {
		return "SMB/CIFS service"
	}
	return "SMB service"
}

func grabWinRM(conn net.Conn) string {
	return "WinRM (Windows Remote Management)"
}

func grabKubernetes(conn net.Conn) string {
	return "Kubernetes API server"
}

func grabElasticsearch(conn net.Conn) string {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if strings.Contains(body, "elasticsearch") || strings.Contains(body, "Elasticsearch") {
		re := `"number"\s*:\s*"([\d.]+)"`
		idx := strings.Index(body, `"number"`)
		if idx >= 0 {
			sub := body[idx:]
			start := strings.Index(sub, `"`) + 1
			if start > 0 {
				sub = sub[start+strings.Index(sub[start:], `"`)+1:]
				end := strings.Index(sub, `"`)
				if end > 0 {
					return "Elasticsearch " + sub[:end]
				}
			}
		}
		_ = re
		return "Elasticsearch"
	}
	return ""
}

func grabPrometheus(conn net.Conn) string {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	fmt.Fprintf(conn, "GET /metrics HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "# HELP") || strings.Contains(string(buf[:n]), "go_goroutines") {
		return "Prometheus metrics endpoint"
	}
	return ""
}

func grabKibana(conn net.Conn) string {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	fmt.Fprintf(conn, "GET /api/status HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if strings.Contains(body, "kibana") || strings.Contains(body, "Kibana") {
		return "Kibana dashboard"
	}
	return ""
}

func grabCassandra(conn net.Conn) string {
	startup := []byte{
		0x04, 0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x16,
		0x00, 0x01,
		0x00, 0x0b, 'C', 'Q', 'L', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N',
		0x00, 0x05, '3', '.', '0', '.', '0',
	}
	if _, err := conn.Write(startup); err != nil {
		return ""
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 4 && buf[0] == 0x84 {
		return "Cassandra database"
	}
	return ""
}

func grabRTSP(conn net.Conn) string {
	fmt.Fprintf(conn, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "RTSP/") {
			return "RTSP " + line
		}
	}
	return ""
}

func grabSIP(conn net.Conn) string {
	fmt.Fprintf(conn, "OPTIONS sip:probe@%s SIP/2.0\r\nVia: SIP/2.0/TCP recon-x:5060\r\nMax-Forwards: 70\r\nFrom: <sip:probe@recon-x>;tag=probe\r\nTo: <sip:probe@%s>\r\nCall-ID: recon-x-probe\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", conn.RemoteAddr().String(), conn.RemoteAddr().String())
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SIP/") {
			return "SIP service: " + line
		}
	}
	return ""
}

func GuessService(banner string, port int) string {
	if banner == "" {
		return ""
	}
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh"):
		return "ssh"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp") || strings.HasPrefix(lower, "220"):
		return "smtp"
	case strings.Contains(lower, "http"):
		return "http"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "postgresql") || strings.Contains(lower, "postgres"):
		return "postgresql"
	case strings.Contains(lower, "redis"):
		return "redis"
	case strings.Contains(lower, "mongodb"):
		return "mongodb"
	case strings.Contains(lower, "zookeeper"):
		return "zookeeper"
	case strings.Contains(lower, "activemq"):
		return "activemq"
	case strings.Contains(lower, "memcached"):
		return "memcached"
	case strings.Contains(lower, "elasticsearch"):
		return "elasticsearch"
	case strings.Contains(lower, "kibana"):
		return "kibana"
	case strings.Contains(lower, "kafka"):
		return "kafka"
	case strings.Contains(lower, "rabbitmq"):
		return "rabbitmq"
	case strings.Contains(lower, "vnc") || strings.Contains(lower, "rfb"):
		return "vnc"
	case strings.Contains(lower, "rdp") || strings.Contains(lower, "terminal"):
		return "rdp"
	case strings.Contains(lower, "ldap"):
		return "ldap"
	case strings.Contains(lower, "smb") || strings.Contains(lower, "cifs"):
		return "smb"
	}
	_ = port
	return ""
}
