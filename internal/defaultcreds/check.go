package defaultcreds

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL        string
	Username   string
	Password   string
	StatusCode int
	Found      bool
}

var credPairs = [][2]string{
	{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"}, {"admin", "admin123"},
	{"root", "root"}, {"root", "password"}, {"root", "toor"}, {"administrator", "administrator"},
	{"admin", "1234"}, {"admin", "pass"}, {"user", "user"}, {"test", "test"},
	{"admin", ""}, {"guest", "guest"},
}

func Check(loginURLs []string, onFound func(Result)) []Result {
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 20)
	)

	for _, loginURL := range loginURLs {
		for _, pair := range credPairs {
			sem <- struct{}{}
			wg.Add(1)
			go func(loginURL string, username, password string) {
				defer func() { <-sem; wg.Done() }()

				found := tryLogin(client, loginURL, username, password)
				if found != nil {
					mu.Lock()
					results = append(results, *found)
					if onFound != nil {
						onFound(*found)
					}
					mu.Unlock()
				}
			}(loginURL, pair[0], pair[1])
		}
	}
	wg.Wait()
	return results
}

func isSuccess(statusCode int, body string) bool {
	if statusCode != 200 {
		return false
	}
	low := strings.ToLower(body)
	if strings.Contains(low, "invalid") || strings.Contains(low, "incorrect") {
		return false
	}
	return strings.Contains(low, "dashboard") ||
		strings.Contains(low, "logout") ||
		strings.Contains(low, "welcome") ||
		strings.Contains(low, "admin")
}

func tryLogin(client *http.Client, loginURL, username, password string) *Result {
	formData1 := url.Values{
		"username": {username},
		"password": {password},
	}
	if r := postForm(client, loginURL, formData1, username, password); r != nil {
		return r
	}

	formData2 := url.Values{
		"email": {username},
		"pass":  {password},
	}
	if r := postForm(client, loginURL, formData2, username, password); r != nil {
		return r
	}

	if r := tryBasicAuth(client, loginURL, username, password); r != nil {
		return r
	}

	return nil
}

func postForm(client *http.Client, loginURL string, data url.Values, username, password string) *Result {
	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if isSuccess(resp.StatusCode, string(body)) {
		return &Result{
			URL:        loginURL,
			Username:   username,
			Password:   password,
			StatusCode: resp.StatusCode,
			Found:      true,
		}
	}
	return nil
}

func tryBasicAuth(client *http.Client, loginURL, username, password string) *Result {
	req, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return nil
	}
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+creds)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if isSuccess(resp.StatusCode, string(body)) {
		return &Result{
			URL:        loginURL,
			Username:   username,
			Password:   password,
			StatusCode: resp.StatusCode,
			Found:      true,
		}
	}
	return nil
}
