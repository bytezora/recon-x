package dirbust

import (
"crypto/tls"
_ "embed"
"io"
"net/http"
"os"
"strings"
"sync"
"time"
)

//go:embed paths.txt
var defaultPaths string

const requestTimeout = 8 * time.Second

type Hit struct {
URL        string
Path       string
StatusCode int
RedirectTo string
}

func interesting(code int) bool {
switch code {
case 200, 201, 204, 301, 302, 307, 308, 401, 403:
return true
}
return false
}

var client = &http.Client{
Timeout: requestTimeout,
Transport: &http.Transport{
TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
},
CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
return http.ErrUseLastResponse
},
}

func Bust(baseURLs []string, pathsFile string, threads int, onFound func(Hit)) []Hit {
baseURLs = DedupeURLs(baseURLs)
paths    := loadPaths(pathsFile)
results  := make([]Hit, 0, 32)
mu       := sync.Mutex{}
sem      := make(chan struct{}, threads)
wg       := sync.WaitGroup{}

for _, base := range baseURLs {
base = strings.TrimRight(base, "/")
for _, path := range paths {
sem <- struct{}{}
wg.Add(1)

go func(u, p string) {
defer func() { <-sem; wg.Done() }()

target := u + p
resp, err := client.Get(target)
if err != nil {
return
}
io.Copy(io.Discard, resp.Body) //nolint:errcheck
resp.Body.Close()

if !interesting(resp.StatusCode) {
return
}

h := Hit{
URL:        target,
Path:       p,
StatusCode: resp.StatusCode,
RedirectTo: resp.Header.Get("Location"),
}
mu.Lock()
results = append(results, h)
mu.Unlock()

if onFound != nil {
onFound(h)
}
}(base, path)
}
}

wg.Wait()
return results
}

func DedupeURLs(urls []string) []string {
seen := make(map[string]bool, len(urls))
out  := make([]string, 0, len(urls))
for _, u := range urls {
if !seen[u] {
seen[u] = true
out = append(out, u)
}
}
return out
}

func loadPaths(path string) []string {
if path != "" {
data, err := os.ReadFile(path)
if err == nil {
return strings.Fields(string(data))
}
}
return strings.Fields(defaultPaths)
}
