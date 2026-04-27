package favicon

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL  string `json:"url"`
	Hash int32  `json:"hash"`
	B64  string `json:"b64"`
}

var client = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
	},
}

func Scan(baseURLs []string, threads int, onFound func(Result)) []Result {
	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)
	for _, u := range baseURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			r, ok := scanOne(u)
			if !ok {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
			if onFound != nil {
				onFound(r)
			}
		}(u)
	}
	wg.Wait()
	return results
}

func scanOne(baseURL string) (Result, bool) {
	faviconURL := strings.TrimRight(baseURL, "/") + "/favicon.ico"
	data, err := fetchBytes(faviconURL)
	if err != nil || len(data) == 0 {
		return Result{}, false
	}
	b64 := encodeChunked(data)
	hash := murmur3([]byte(b64))
	return Result{
		URL:  faviconURL,
		Hash: hash,
		B64:  b64,
	}, true
}

func fetchBytes(url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil
	}
	return io.ReadAll(resp.Body)
}

func encodeChunked(data []byte) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

func murmur3(data []byte) int32 {
	h1 := uint32(0)
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= 0xcc9e2d51
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= 0x1b873593
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	k1 := uint32(0)
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= 0xcc9e2d51
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= 0x1b873593
		h1 ^= k1
	}
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1)
}
