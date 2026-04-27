// Package banner grabs service banners from open TCP ports.
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

// Grab connects to ip:port and returns the service banner.
// Returns an empty string if the connection fails or no banner is sent.
func Grab(ip string, port int) string {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return GrabConn(conn, port)
}

// GrabConn reads a service banner from an already-connected TCP socket.
// Callers are responsible for closing conn after this returns.
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

	// Generic: read first line (works for SSH, FTP, SMTP, etc.)
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

// grabHTTP sends an HTTP HEAD request and extracts the Server header value.
func grabHTTP(conn net.Conn) string {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host) //nolint:errcheck

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // end of HTTP headers
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

// grabRedis sends INFO server and parses the redis_version field.
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

// grabMySQL reads the MySQL initial handshake packet and extracts the server version.
// MySQL sends: 3-byte payload length + 1-byte seq + 1-byte protocol(10) + null-terminated version string.
func grabMySQL(conn net.Conn) string {
	// Read 4-byte packet header
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
	// Protocol version 10 = MySQL 4.1+
	if payload[0] != 10 {
		return ""
	}
	// Version string is null-terminated starting at payload[1]
	null := bytes.IndexByte(payload[1:], 0)
	if null < 0 {
		return ""
	}
	full := string(payload[1 : 1+null]) // e.g. "8.0.26-community"
	// Strip distribution suffix to get clean version: "8.0.26"
	if dash := strings.IndexByte(full, '-'); dash > 0 {
		full = full[:dash]
	}
	return full + "-MySQL"
}

// grabMemcached sends "version\r\n" and parses "VERSION X.Y.Z"
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

// grabZookeeper sends "srvr\r\n" and parses the version line
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

// grabActiveMQ reads the OpenWire banner from port 61616
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

// grabPostgres sends a PostgreSQL v3.0 startup message and reads ParameterStatus
// messages looking for server_version. Only works when server trusts the connection.
func grabPostgres(conn net.Conn) string {
	// Startup message (no type byte): length(4BE) + protocol(4BE) + params
	params := []byte("user\x00postgres\x00database\x00postgres\x00\x00")
	totalLen := 8 + len(params)
	startup := make([]byte, totalLen)
	startup[0] = byte(totalLen >> 24)
	startup[1] = byte(totalLen >> 16)
	startup[2] = byte(totalLen >> 8)
	startup[3] = byte(totalLen)
	startup[4], startup[5], startup[6], startup[7] = 0, 3, 0, 0 // protocol 3.0
	copy(startup[8:], params)

	if _, err := conn.Write(startup); err != nil {
		return ""
	}

	// Read backend messages looking for server_version in ParameterStatus
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
		case 'S': // ParameterStatus: name\0value\0
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
		case 'R': // AuthenticationRequest
			if bodyLen >= 4 {
				authType := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
				if authType != 0 {
					return "" // requires password — version not available
				}
				// authType == 0 → AuthenticationOk, continue reading ParameterStatus
			}
		case 'E', 'Z': // ErrorResponse or ReadyForQuery — stop
			return ""
		}
	}
	return ""
}

// grabMongoDB sends an OP_MSG isMaster command and extracts the server version.
func grabMongoDB(conn net.Conn) string {
	// BSON document: {isMaster:1, $db:"admin"} — length 34 = 0x22
	bsonDoc := []byte{
		0x22, 0x00, 0x00, 0x00, // doc length = 34
		0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // int32 key
		0x01, 0x00, 0x00, 0x00, // value = 1
		0x02, '$', 'd', 'b', 0x00, // string key "$db"
		0x06, 0x00, 0x00, 0x00, 'a', 'd', 'm', 'i', 'n', 0x00, // value = "admin"
		0x00, // doc terminator
	}
	msgLen := 16 + 4 + 1 + len(bsonDoc) // header + flagBits + section kind + BSON
	le32 := func(v uint32) []byte {
		return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	}
	msg := make([]byte, 0, msgLen)
	msg = append(msg, le32(uint32(msgLen))...)
	msg = append(msg, le32(1)...)    // requestID
	msg = append(msg, le32(0)...)    // responseTo
	msg = append(msg, le32(2013)...) // opCode OP_MSG
	msg = append(msg, le32(0)...)    // flagBits
	msg = append(msg, 0)             // section kind = body
	msg = append(msg, bsonDoc...)

	if _, err := conn.Write(msg); err != nil {
		return ""
	}

	// Read response header (16 bytes)
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
	// body[0:4]=flagBits, body[4]=section kind, body[5:]=BSON
	if len(body) < 5 || body[4] != 0 {
		return ""
	}
	// Scan BSON for string field named "version"
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
