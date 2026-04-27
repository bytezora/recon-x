package adminpanel

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpcheck"
)

type Result struct {
	URL        string
	Path       string
	StatusCode int
	Title      string
}

var adminPaths = []string{
	"/admin", "/admin/", "/admin/login", "/admin/index.php", "/admin/dashboard",
	"/administrator", "/administrator/index.php", "/administrator/login.php",
	"/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-admin/admin.php",
	"/wp-admin/options-general.php",
	"/login", "/login.php", "/login.html", "/signin", "/sign-in",
	"/panel", "/panel/", "/cpanel", "/cPanel",
	"/dashboard", "/dashboard/login",
	"/manage", "/management", "/manager", "/manager/html",
	"/webadmin", "/admincp", "/admin_area",
	"/phpmyadmin", "/phpmyadmin/", "/pma", "/db/",
	"/moderator", "/account/login", "/user/login",
	"/controlpanel", "/control", "/portal", "/backend",
	"/siteadmin", "/site_admin", "/system",
	"/secure", "/maintenance", "/install", "/setup",
	"/_admin", "/cms/admin", "/admin2", "/admin3",
	"/joomla/administrator", "/administrator/index.php",
	"/drupal/user/login", "/user/login",
	"/typo3/index.php", "/typo3",
	"/magento/admin", "/index.php/admin",
	"/admin/account.php", "/admin/main.php", "/admin/home.php",
	"/admin/controlpanel.php", "/admin/cp.php",
	"/.env", "/.git/config",
}

var interestingCodes = map[int]bool{
	200: true, 301: true, 302: true, 403: true, 401: true,
}

func Discover(httpResults []httpcheck.Result, threads int, onFound func(Result)) []Result {
	if threads <= 0 {
		threads = 30
	}
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type job struct {
		base string
		path string
	}

	seen := make(map[string]bool)
	var jobs []job
	for _, h := range httpResults {
		base := extractBase(h.URL)
		if base == "" {
			continue
		}
		for _, p := range adminPaths {
			key := base + p
			if seen[key] {
				continue
			}
			seen[key] = true
			jobs = append(jobs, job{base: base, path: p})
		}
	}

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)

	for _, j := range jobs {
		sem <- struct{}{}
		wg.Add(1)
		go func(j job) {
			defer func() { <-sem; wg.Done() }()
			target := j.base + j.path
			resp, err := client.Get(target)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if !interestingCodes[resp.StatusCode] {
				return
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			title := extractTitle(string(data))
			r := Result{
				URL:        j.base,
				Path:       j.path,
				StatusCode: resp.StatusCode,
				Title:      title,
			}
			mu.Lock()
			results = append(results, r)
			if onFound != nil {
				onFound(r)
			}
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	return results
}

func extractBase(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func extractTitle(body string) string {
	low := strings.ToLower(body)
	s := strings.Index(low, "<title>")
	e := strings.Index(low, "</title>")
	if s == -1 || e <= s+7 {
		return ""
	}
	title := strings.TrimSpace(body[s+7 : e])
	if len(title) > 80 {
		return title[:80] + "..."
	}
	return title
}
