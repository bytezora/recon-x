package screenshot

import (
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

type Result struct {
	URL     string `json:"url"`
	DataURI string `json:"data_uri,omitempty"`
	Error   string `json:"error,omitempty"`
}

func Capture(urls []string, threads int, onFound func(Result)) []Result {
	browser := findBrowser()
	if browser == "" {
		return nil
	}

	cap := threads
	if cap > 3 {
		cap = 3
	}

	var results []Result
	mu  := sync.Mutex{}
	sem := make(chan struct{}, cap)
	wg  := sync.WaitGroup{}

	for _, u := range urls {
		sem <- struct{}{}
		wg.Add(1)
		go func(url string) {
			defer func() { <-sem; wg.Done() }()
			r := take(browser, url)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
			if onFound != nil && r.DataURI != "" {
				onFound(r)
			}
		}(u)
	}
	wg.Wait()
	return results
}

func take(browser, url string) Result {
	tmp, err := os.CreateTemp("", "recon-x-*.png")
	if err != nil {
		return Result{URL: url, Error: err.Error()}
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	args := []string{
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--window-size=1280,800",
		"--screenshot=" + tmp.Name(),
		"--ignore-certificate-errors",
		"--disable-extensions",
		url,
	}

	cmd := exec.Command(browser, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			return Result{URL: url, Error: err.Error()}
		}
	case <-time.After(20 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill() //nolint:errcheck
		}
		return Result{URL: url, Error: "screenshot timeout"}
	}

	data, err := os.ReadFile(tmp.Name())
	if err != nil || len(data) == 0 {
		return Result{URL: url, Error: "no image data"}
	}

	return Result{
		URL:     url,
		DataURI: "data:image/png;base64," + base64.StdEncoding.EncodeToString(data),
	}
}

func findBrowser() string {
	if runtime.GOOS == "windows" {
		for _, path := range []string{
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		} {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		return ""
	}
	for _, name := range []string{
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
