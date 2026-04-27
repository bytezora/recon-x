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
	conn.SetDeadline(time.Now().Add(readTimeout)) //nolint:errcheck

	switch port {
	case 6379:
		return grabRedis(conn)
	case 3306:
		return grabMySQL(conn)
	case 5432:
		return grabPostgres(conn)
	case 27017:
		return grabMongoDB(conn)
	case 11211:
		return grabMemcached(conn)
	case 2181:
		return grabZookeeper(conn)
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
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host) //nolint:errcheck

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
	fmt.Fprintf(conn, "INFO server\r\n") //nolint:errcheck
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
	fmt.Fprintf(conn, "version\r\n") //nolint:errcheck
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
	fmt.Fprintf(conn, "srvr\r\n") //nolint:errcheck
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
	case 80, 443, 7001, 8080, 8081, 8161, 8443, 8888, 3000, 4000, 5000, 5601, 6443, 8000, 8001, 8008, 8983, 9000, 9200, 15672:
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
