package report

import (
"fmt"
"html/template"
"os"
"strings"
"time"

"github.com/bytezora/recon-x/internal/axfr"
"github.com/bytezora/recon-x/internal/buckets"
"github.com/bytezora/recon-x/internal/dirbust"
"github.com/bytezora/recon-x/internal/ghsearch"
"github.com/bytezora/recon-x/internal/httpcheck"
"github.com/bytezora/recon-x/internal/jsscan"
"github.com/bytezora/recon-x/internal/openredirect"
"github.com/bytezora/recon-x/internal/portscan"
"github.com/bytezora/recon-x/internal/screenshot"
"github.com/bytezora/recon-x/internal/subdomain"
"github.com/bytezora/recon-x/internal/tlscheck"
"github.com/bytezora/recon-x/internal/vulns"
"github.com/bytezora/recon-x/internal/waf"
"github.com/bytezora/recon-x/internal/whois"
"github.com/bytezora/recon-x/internal/asn"
"github.com/bytezora/recon-x/internal/bypass"
"github.com/bytezora/recon-x/internal/cors"
"github.com/bytezora/recon-x/internal/adminpanel"
"github.com/bytezora/recon-x/internal/defaultcreds"
"github.com/bytezora/recon-x/internal/emailsec"
"github.com/bytezora/recon-x/internal/favicon"
"github.com/bytezora/recon-x/internal/ratelimit"
"github.com/bytezora/recon-x/internal/sqli"
"github.com/bytezora/recon-x/internal/graphql"
"github.com/bytezora/recon-x/internal/takeover"
"github.com/bytezora/recon-x/internal/finding"
"github.com/bytezora/recon-x/internal/templates"
"github.com/bytezora/recon-x/internal/vhost"
)

type Data struct {
Target      string
GeneratedAt string
Subdomains  []subdomain.Result
Ports       []portscan.Result
HTTP        []httpcheck.Result
Vulns       []vulns.Match
WAFs        []waf.Result
DirHits     []dirbust.Hit
JSFindings  []jsscan.Finding
GHFindings  []ghsearch.Finding
Buckets     []buckets.Result
TLS         []tlscheck.Result
Redirects   []openredirect.Result
AXFR        []axfr.Result
WHOIS       *whois.Result
Screenshots []screenshot.Result
Takeover  []takeover.Result
CORS      []cors.Result
Bypass    []bypass.Result
VHosts    []vhost.Result
Favicons  []favicon.Result
ASN       []asn.Result
GraphQL   []graphql.Result
EmailSec     *emailsec.Result
AdminPanel   []adminpanel.Result
SQLi         []sqli.Result
DefaultCreds []defaultcreds.Result
RateLimit    []ratelimit.Result
Templates    []templates.Match
Findings     []finding.Finding
}

const tmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>recon-x :: {{.Target}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0a;
  --bg2:#111111;
  --bg3:#181818;
  --bg4:#1e1e1e;
  --line:#2a2a2a;
  --text:#c8c8c8;
  --dim:#606060;
  --hi:#39ff14;
  --hi2:#2acc0f;
  --warn:#888888;
  --alert:#c0c0c0;
  --font:"Lucida Console","Courier New",Courier,monospace;
}
html,body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.6;height:100%}
body{display:flex;flex-direction:column}

/* ── header ── */
header{
  background:var(--bg2);
  border-bottom:1px solid var(--line);
  padding:1rem 2rem;
  display:flex;
  align-items:center;
  gap:1.2rem;
  flex-shrink:0;
}
.logo{font-size:1.3rem;font-weight:700;color:var(--hi);letter-spacing:4px}
.logo-sep{color:var(--line);font-size:1.1rem}
.target{color:var(--text);font-size:1rem;font-weight:700}
.meta{color:var(--dim);font-size:.72rem;margin-left:auto}

/* ── summary cards ── */
.summary{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(90px,1fr));
  gap:0;
  border-bottom:1px solid var(--line);
  flex-shrink:0;
}
.card{
  background:var(--bg2);
  border-right:1px solid var(--line);
  padding:.7rem 1rem;
  text-align:center;
  cursor:pointer;
  transition:background .15s;
  user-select:none;
}
.card:last-child{border-right:none}
.card:hover{background:var(--bg3)}
.card.active{background:var(--bg3);border-bottom:2px solid var(--hi);margin-bottom:-1px}
.card .num{font-size:1.5rem;font-weight:700;color:var(--hi);line-height:1.2}
.card .label{color:var(--dim);font-size:.65rem;letter-spacing:2px;margin-top:.2rem;text-transform:uppercase}

/* ── tab layout ── */
.tabs-wrap{flex:1;overflow:hidden;display:flex;flex-direction:column}
.tab-content{display:none;flex:1;overflow-y:auto;padding:1.5rem 2rem}
.tab-content.active{display:block}

/* ── section heading ── */
h2{
  font-size:.78rem;
  letter-spacing:3px;
  text-transform:uppercase;
  color:var(--hi);
  margin-bottom:.8rem;
  padding-bottom:.4rem;
  border-bottom:1px solid var(--line);
}

/* ── tables ── */
table{
  width:100%;
  border-collapse:collapse;
  background:var(--bg2);
  border:1px solid var(--line);
}
th{
  background:var(--bg3);
  padding:.5rem 1rem;
  text-align:left;
  font-size:.68rem;
  letter-spacing:2px;
  color:var(--dim);
  text-transform:uppercase;
  border-bottom:1px solid var(--line);
  position:sticky;top:0;z-index:1;
}
td{
  padding:.5rem 1rem;
  border-top:1px solid var(--line);
  font-size:.78rem;
  word-break:break-all;
  vertical-align:top;
}
tr:hover td{background:var(--bg4)}

/* ── tags ── */
.tag{
  display:inline-block;
  padding:.1rem .4rem;
  font-size:.68rem;
  border:1px solid var(--line);
  color:var(--dim);
  margin:.1rem .1rem .1rem 0;
  white-space:nowrap;
}
.tag-hi{border-color:var(--hi2);color:var(--hi)}
.tag-warn{border-color:var(--warn);color:var(--warn)}
.tag-alert{border-color:var(--alert);color:var(--alert)}

/* ── severity ── */
.sev-crit{color:var(--hi);font-weight:700}
.sev-high{color:#b0b0b0;font-weight:700}
.sev-med{color:var(--dim)}

/* ── misc ── */
a{color:var(--hi2);text-decoration:none}
a:hover{text-decoration:underline}
.empty{color:var(--dim);padding:1rem 0;font-size:.78rem}
.mono{font-family:var(--font);font-size:.72rem;color:var(--dim)}

/* ── search bar ── */
.search-wrap{padding:.5rem 2rem .4rem;border-bottom:1px solid var(--line);background:var(--bg2);flex-shrink:0;display:none}
.search-wrap.visible{display:block}
.search-input{
  background:var(--bg);
  border:1px solid var(--line);
  color:var(--text);
  font-family:var(--font);
  font-size:.78rem;
  padding:.3rem .7rem;
  width:100%;
  max-width:400px;
  outline:none;
}
.search-input:focus{border-color:var(--hi)}

/* ── critical bar ── */
.crit-bar{
  background:var(--bg2);
  border-bottom:1px solid var(--line);
  padding:.4rem 2rem;
  font-size:.72rem;
  color:var(--dim);
  letter-spacing:1px;
  flex-shrink:0;
  display:flex;
  gap:1.2rem;
}
.crit-item{display:flex;align-items:center;gap:.4rem}
.crit-num{font-weight:700}
.crit-num.red{color:var(--hi)}
.crit-num.yellow{color:#c8a000}
.crit-num.green{color:#00ff87}

/* ── cvss score ── */
.cvss-crit{color:var(--hi);font-weight:700}
.cvss-high{color:#c0c0c0;font-weight:700}
.cvss-med{color:#888}
.cvss-low{color:var(--dim)}

.findings-grid{display:flex;flex-direction:column;gap:12px}
.finding-card{border:1px solid #333;border-radius:8px;padding:16px;background:#111}
.finding-card.sev-critical{border-left:4px solid #ff2244}
.finding-card.sev-high{border-left:4px solid #ff6600}
.finding-card.sev-medium{border-left:4px solid #ffcc00}
.finding-card.sev-low{border-left:4px solid #44aaff}
.finding-header{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.finding-title{font-size:1rem;font-weight:600;margin-bottom:10px;color:#f0f0f0}
.badge{font-size:0.7rem;padding:2px 8px;border-radius:4px;font-weight:700;text-transform:uppercase}
.sev-badge{background:#333;color:#fff}
.finding-card.sev-critical .sev-badge{background:#ff2244;color:#fff}
.finding-card.sev-high .sev-badge{background:#ff6600;color:#fff}
.finding-card.sev-medium .sev-badge{background:#ffcc00;color:#000}
.finding-card.sev-low .sev-badge{background:#44aaff;color:#000}
.conf-badge{background:#1a3a1a;color:#44ff88}
.manual-badge{background:#3a2a00;color:#ffaa00}
.finding-type{font-size:0.75rem;color:#888;margin-left:auto}
.finding-table{width:100%;border-collapse:collapse;font-size:0.85rem}
.finding-table tr{border-bottom:1px solid #222}
.fk{color:#888;padding:4px 8px 4px 0;white-space:nowrap;vertical-align:top;width:80px}
.fv{color:#ccc;padding:4px 0}
.fv code{background:#1a1a1a;padding:2px 6px;border-radius:3px;font-family:monospace;color:#00ff88;word-break:break-all}

</style>
</head>
<body>

<header>
  <span class="logo">RECON-X</span>
  <span class="logo-sep">//</span>
  <span class="target">{{.Target}}</span>
  <span class="meta">{{.GeneratedAt}}</span>
</header>

<div class="crit-bar">
  <span class="crit-item"><span class="crit-num red">{{len .Vulns}}</span> cve</span>
  <span class="crit-item"><span class="crit-num {{if .SQLi}}red{{else}}green{{end}}">{{len .SQLi}}</span> sqli</span>
  <span class="crit-item"><span class="crit-num {{if .Takeover}}red{{else}}green{{end}}">{{len .Takeover}}</span> takeover</span>
  <span class="crit-item"><span class="crit-num {{if .CORS}}yellow{{else}}green{{end}}">{{len .CORS}}</span> cors</span>
  <span class="crit-item"><span class="crit-num {{if .DefaultCreds}}red{{else}}green{{end}}">{{len .DefaultCreds}}</span> def-creds</span>
  <span class="crit-item"><span class="crit-num">{{len .Subdomains}}</span> subdomains</span>
  <span class="crit-item"><span class="crit-num">{{len .Ports}}</span> open ports</span>
</div>

<div class="search-wrap" id="search-wrap">
  <input class="search-input" id="search-input" type="text" placeholder="filter rows..." oninput="filterTable(this.value)"/>
</div>

<div class="summary">
  <div class="card active" onclick="show('subdomains',this)">
    <div class="num">{{len .Subdomains}}</div>
    <div class="label">subdomains</div>
  </div>
  <div class="card" onclick="show('ports',this)">
    <div class="num">{{len .Ports}}</div>
    <div class="label">open ports</div>
  </div>
  <div class="card" onclick="show('http',this)">
    <div class="num">{{len .HTTP}}</div>
    <div class="label">http</div>
  </div>
  <div class="card" onclick="show('vulns',this)">
    <div class="num">{{len .Vulns}}</div>
    <div class="label">cve</div>
  </div>
  <div class="card" onclick="show('waf',this)">
    <div class="num">{{len .WAFs}}</div>
    <div class="label">waf</div>
  </div>
  <div class="card" onclick="show('dirs',this)">
    <div class="num">{{len .DirHits}}</div>
    <div class="label">paths</div>
  </div>
  <div class="card" onclick="show('js',this)">
    <div class="num">{{len .JSFindings}}</div>
    <div class="label">js finds</div>
  </div>
  <div class="card" onclick="show('github',this)">
    <div class="num">{{len .GHFindings}}</div>
    <div class="label">github leaks</div>
  </div>
  <div class="card" onclick="show('buckets',this)">
    <div class="num">{{len .Buckets}}</div>
    <div class="label">buckets</div>
  </div>
  <div class="card" onclick="show('tls',this)">
    <div class="num">{{len .TLS}}</div>
    <div class="label">tls</div>
  </div>
  <div class="card" onclick="show('redirect',this)">
    <div class="num">{{len .Redirects}}</div>
    <div class="label">redirects</div>
  </div>
  <div class="card" onclick="show('axfr',this)">
    <div class="num">{{len .AXFR}}</div>
    <div class="label">axfr</div>
  </div>
  <div class="card" onclick="show('whois',this)">
    <div class="num">{{if .WHOIS}}1{{else}}0{{end}}</div>
    <div class="label">whois</div>
  </div>
  <div class="card" onclick="show('screenshots',this)">
    <div class="num">{{len .Screenshots}}</div>
    <div class="label">screens</div>
  </div>
  <div class="card" onclick="show('takeover',this)">
    <div class="num">{{len .Takeover}}</div>
    <div class="label">takeover</div>
  </div>
  <div class="card" onclick="show('cors',this)">
    <div class="num">{{len .CORS}}</div>
    <div class="label">cors</div>
  </div>
  <div class="card" onclick="show('bypass',this)">
    <div class="num">{{len .Bypass}}</div>
    <div class="label">403 bypass</div>
  </div>
  <div class="card" onclick="show('vhosts',this)">
    <div class="num">{{len .VHosts}}</div>
    <div class="label">vhosts</div>
  </div>
  <div class="card" onclick="show('favicons',this)">
    <div class="num">{{len .Favicons}}</div>
    <div class="label">favicons</div>
  </div>
  <div class="card" onclick="show('asn',this)">
    <div class="num">{{len .ASN}}</div>
    <div class="label">asn</div>
  </div>
  <div class="card" onclick="show('graphql',this)">
    <div class="num">{{len .GraphQL}}</div>
    <div class="label">graphql</div>
  </div>
  <div class="card" onclick="show('emailsec',this)">
    <div class="num">{{if .EmailSec}}1{{else}}0{{end}}</div>
    <div class="label">email sec</div>
  </div>
  <div class="card" onclick="show('adminpanel',this)">
    <div class="num">{{len .AdminPanel}}</div>
    <div class="label">admin panels</div>
  </div>
  <div class="card" onclick="show('sqli',this)">
    <div class="num">{{len .SQLi}}</div>
    <div class="label">sqli</div>
  </div>
  <div class="card" onclick="show('defaultcreds',this)">
    <div class="num">{{len .DefaultCreds}}</div>
    <div class="label">def creds</div>
  </div>
  <div class="card" onclick="show('ratelimit',this)">
    <div class="num">{{len .RateLimit}}</div>
    <div class="label">rate limit</div>
  </div>
  <div class="card" onclick="show('findings',this)">
    <div class="num">{{len .Findings}}</div>
    <div class="label">findings</div>
  </div>
</div>

<div class="tabs-wrap">

  <!-- SUBDOMAINS -->
  <div id="tab-subdomains" class="tab-content active">
    <h2>Subdomains</h2>
    {{if .Subdomains}}
    <table>
      <thead><tr><th>#</th><th>Subdomain</th><th>IP Addresses</th></tr></thead>
      <tbody>
      {{range $i,$s := .Subdomains}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td style="color:var(--hi)">{{$s.Subdomain}}</td>
        <td>{{range $s.IPs}}<span class="tag">{{.}}</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no subdomains found ]</p>{{end}}
  </div>

  <!-- PORTS -->
  <div id="tab-ports" class="tab-content">
    <h2>Open Ports</h2>
    {{if .Ports}}
    <table>
      <thead><tr><th>#</th><th>Host</th><th>Port</th><th>IP</th><th>Banner</th></tr></thead>
      <tbody>
      {{range $i,$p := .Ports}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td>{{$p.Host}}</td>
        <td><span class="tag tag-hi">{{$p.Port}}</span></td>
        <td class="mono">{{$p.IP}}</td>
        <td class="mono">{{$p.Banner}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no open ports found ]</p>{{end}}
  </div>

  <!-- HTTP -->
  <div id="tab-http" class="tab-content">
    <h2>HTTP Services</h2>
    {{if .HTTP}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technologies</th><th>Missing Sec Headers</th></tr></thead>
      <tbody>
      {{range $i,$h := .HTTP}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td><a href="{{$h.URL}}" target="_blank">{{$h.URL}}</a></td>
        <td>
          {{if eq $h.StatusCode 200}}<span class="tag tag-hi">{{$h.StatusCode}}</span>
          {{else if eq $h.StatusCode 403}}<span class="tag tag-alert">{{$h.StatusCode}}</span>
          {{else if eq $h.StatusCode 401}}<span class="tag tag-alert">{{$h.StatusCode}}</span>
          {{else}}<span class="tag tag-warn">{{$h.StatusCode}}</span>{{end}}
        </td>
        <td>{{$h.Title}}</td>
        <td class="mono">{{$h.Server}}</td>
        <td>{{range $h.Tech}}<span class="tag">{{.}}</span>{{end}}</td>
        <td>{{range $h.MissingHeaders}}<span class="tag tag-warn">{{.}}</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no http services found ]</p>{{end}}
  </div>

  <!-- CVE -->
  <div id="tab-vulns" class="tab-content">
    <h2>CVE Matches</h2>
    {{if .Vulns}}
    <table>
      <thead><tr><th>#</th><th>Host</th><th>Port</th><th>CVE</th><th>CVSS</th><th>Severity</th><th>Description</th><th>Banner / Header</th><th>Confidence</th></tr></thead>
      <tbody>
      {{range $i,$v := .Vulns}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td>{{$v.Host}}</td>
        <td>{{if $v.Port}}<span class="tag tag-hi">{{$v.Port}}</span>{{else}}<span class="tag">HTTP</span>{{end}}</td>
        <td><a href="{{$v.Link}}" target="_blank">{{$v.CVE}}</a></td>
        <td>
          {{if ge $v.CVSS 9.0}}<span class="cvss-crit">{{printf "%.1f" $v.CVSS}}</span>
          {{else if ge $v.CVSS 7.0}}<span class="cvss-high">{{printf "%.1f" $v.CVSS}}</span>
          {{else if ge $v.CVSS 4.0}}<span class="cvss-med">{{printf "%.1f" $v.CVSS}}</span>
          {{else}}<span class="cvss-low">{{printf "%.1f" $v.CVSS}}</span>{{end}}
        </td>
        <td>
          {{if eq $v.Severity "CRITICAL"}}<span class="sev-crit">CRITICAL</span>
          {{else if eq $v.Severity "HIGH"}}<span class="sev-high">HIGH</span>
          {{else}}<span class="sev-med">{{$v.Severity}}</span>{{end}}
        </td>
        <td>{{$v.Description}}</td>
        <td class="mono">{{$v.Banner}}</td>
        <td>{{if eq $v.Confidence "confirmed"}}<span class="tag tag-alert" style="font-weight:700">CONFIRMED</span>{{else if eq $v.Confidence "high"}}<span class="tag tag-hi">high</span>{{else if eq $v.Confidence "medium"}}<span class="tag">medium</span>{{else}}<span class="tag" style="color:var(--dim)">low</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no cve matches found ]</p>{{end}}
  </div>

  <!-- WAF -->
  <div id="tab-waf" class="tab-content">
    <h2>WAF Detection</h2>
    {{if .WAFs}}
    <table>
      <thead><tr><th>#</th><th>Host</th><th>WAF</th><th>URL</th></tr></thead>
      <tbody>
      {{range $i,$w := .WAFs}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td>{{$w.Host}}</td>
        <td><span class="tag tag-hi">{{$w.WAF}}</span></td>
        <td><a href="{{$w.URL}}" target="_blank">{{$w.URL}}</a></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no waf detected ]</p>{{end}}
  </div>

  <!-- DIRS -->
  <div id="tab-dirs" class="tab-content">
    <h2>Directory Brute-force</h2>
    {{if .DirHits}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Path</th><th>Status</th><th>Redirect To</th></tr></thead>
      <tbody>
      {{range $i,$d := .DirHits}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td><a href="{{$d.URL}}" target="_blank">{{$d.URL}}</a></td>
        <td class="mono">{{$d.Path}}</td>
        <td>
          {{if eq $d.StatusCode 200}}<span class="tag tag-hi">{{$d.StatusCode}}</span>
          {{else if eq $d.StatusCode 403}}<span class="tag tag-alert">{{$d.StatusCode}}</span>
          {{else if eq $d.StatusCode 401}}<span class="tag tag-alert">{{$d.StatusCode}}</span>
          {{else}}<span class="tag tag-warn">{{$d.StatusCode}}</span>{{end}}
        </td>
        <td class="mono">{{if $d.RedirectTo}}<a href="{{$d.RedirectTo}}" target="_blank">{{$d.RedirectTo}}</a>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no interesting paths found ]</p>{{end}}
  </div>

  <!-- JS -->
  <div id="tab-js" class="tab-content">
    <h2>JS Findings — Endpoints &amp; Secrets</h2>
    {{if .JSFindings}}
    <table>
      <thead><tr><th>#</th><th>Kind</th><th>Type</th><th>Value</th><th>Source</th></tr></thead>
      <tbody>
      {{range $i,$j := .JSFindings}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td>
          {{if eq $j.Kind "secret"}}<span class="tag tag-alert">secret</span>
          {{else}}<span class="tag">endpoint</span>{{end}}
        </td>
        <td><span class="tag tag-hi">{{$j.Label}}</span></td>
        <td class="mono">{{$j.Value}}</td>
        <td class="mono"><a href="{{$j.Source}}" target="_blank">{{$j.Source}}</a></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no js findings ]</p>{{end}}
  </div>

  <div id="tab-github" class="tab-content">
    <h2>GitHub Dorking — Exposed Secrets</h2>
    {{if .GHFindings}}
    <table>
      <thead><tr><th>#</th><th>Keyword</th><th>Repository</th><th>Path</th><th>URL</th></tr></thead>
      <tbody>
      {{range $i,$g := .GHFindings}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td><span class="tag tag-alert">{{$g.Keyword}}</span></td>
        <td class="mono">{{$g.Repo}}</td>
        <td class="mono">{{$g.Path}}</td>
        <td class="mono"><a href="{{$g.URL}}" target="_blank">view</a></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no github findings — pass -github-token for better results ]</p>{{end}}
  </div>

  <div id="tab-buckets" class="tab-content">
    <h2>Cloud Buckets — S3 / GCS / Azure</h2>
    {{if .Buckets}}
    <table>
      <thead><tr><th>#</th><th>Provider</th><th>Bucket</th><th>Status</th><th>Code</th><th>URL</th></tr></thead>
      <tbody>
      {{range $i,$b := .Buckets}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td><span class="tag tag-hi">{{$b.Provider}}</span></td>
        <td class="mono">{{$b.Bucket}}</td>
        <td>
          {{if eq $b.Status "public"}}<span class="tag tag-alert">public</span>
          {{else}}<span class="tag">exists</span>{{end}}
        </td>
        <td class="mono">{{$b.Code}}</td>
        <td class="mono"><a href="{{$b.URL}}" target="_blank">{{$b.URL}}</a></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no exposed buckets found ]</p>{{end}}
  </div>

  <div id="tab-tls" class="tab-content">
    <h2>TLS/SSL Analysis</h2>
    {{if .TLS}}
    <table>
      <thead><tr><th>#</th><th>Host</th><th>Port</th><th>Protocol</th><th>Cipher</th><th>Expiry</th><th>Issues</th></tr></thead>
      <tbody>
      {{range $i,$t := .TLS}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$t.Host}}</td>
        <td class="mono">{{$t.Port}}</td>
        <td><span class="tag {{if or (eq $t.Proto "TLS 1.0") (eq $t.Proto "TLS 1.1")}}tag-alert{{else}}tag-hi{{end}}">{{$t.Proto}}</span></td>
        <td class="mono">{{$t.CipherSuite}}</td>
        <td class="mono">{{$t.Expiry}}</td>
        <td>{{range $t.Issues}}<span class="tag tag-alert">{{.}}</span> {{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no TLS services found — requires HTTPS ports ]</p>{{end}}
  </div>

  <div id="tab-redirect" class="tab-content">
    <h2>Open Redirect Detector</h2>
    {{if .Redirects}}
    <table>
      <thead><tr><th>#</th><th>Base URL</th><th>Param</th><th>Location</th><th>Confirmed</th></tr></thead>
      <tbody>
      {{range $i,$r := .Redirects}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$r.BaseURL}}</td>
        <td><span class="tag tag-alert">{{$r.Param}}</span></td>
        <td class="mono">{{$r.Location}}</td>
        <td>{{if $r.Confirmed}}<span class="tag tag-alert">YES</span>{{else}}<span class="tag">NO</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no open redirects found ]</p>{{end}}
  </div>

  <div id="tab-axfr" class="tab-content">
    <h2>DNS Zone Transfer (AXFR)</h2>
    {{if .AXFR}}
    {{range .AXFR}}
    {{if .Success}}
    <h3 style="margin:1rem 0 .5rem;color:var(--alert)">⚠ Zone transfer succeeded via {{.NS}}</h3>
    <table>
      <thead><tr><th>#</th><th>Name</th><th>Type</th><th>Value</th><th>TTL</th></tr></thead>
      <tbody>
      {{range $i,$rec := .Records}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$rec.Name}}</td>
        <td><span class="tag">{{$rec.Type}}</span></td>
        <td class="mono">{{$rec.Value}}</td>
        <td class="mono">{{$rec.TTL}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <p class="empty">[ AXFR refused by {{.NS}} ]</p>
    {{end}}
    {{end}}
    {{else}}<p class="empty">[ DNS zone transfer not attempted or all NS refused ]</p>{{end}}
  </div>

  <div id="tab-whois" class="tab-content">
    <h2>WHOIS / ASN Lookup</h2>
    {{if .WHOIS}}
    <table>
      <tbody>
        <tr><td class="mono" style="width:160px;color:var(--dim)">Registrar</td><td class="mono">{{.WHOIS.Registrar}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">Org</td><td class="mono">{{.WHOIS.Org}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">Country</td><td class="mono">{{.WHOIS.Country}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">Created</td><td class="mono">{{.WHOIS.Created}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">Updated</td><td class="mono">{{.WHOIS.Updated}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">Expires</td><td class="mono">{{.WHOIS.Expires}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">Nameservers</td><td class="mono">{{range .WHOIS.NameSrvs}}{{.}} {{end}}</td></tr>
      </tbody>
    </table>
    {{else}}<p class="empty">[ WHOIS lookup failed or no data ]</p>{{end}}
  </div>

  <div id="tab-screenshots" class="tab-content">
    <h2>HTTP Screenshots</h2>
    {{if .Screenshots}}
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem;margin-top:1rem">
    {{range .Screenshots}}
    <div style="background:var(--bg3);border:1px solid var(--line);padding:.5rem">
      <div class="mono" style="font-size:.7rem;color:var(--dim);margin-bottom:.4rem;word-break:break-all">{{.URL}}</div>
      {{if .DataURI}}
      <img src="{{.DataURI}}" style="width:100%;border:1px solid var(--line)" alt="{{.URL}}"/>
      {{else}}
      <p class="empty" style="height:60px;display:flex;align-items:center;justify-content:center">[ {{.Error}} ]</p>
      {{end}}
    </div>
    {{end}}
    </div>
    {{else}}<p class="empty">[ no screenshots — headless browser not found ]</p>{{end}}
  </div>

  <div id="tab-takeover" class="tab-content">
    <h2>Subdomain Takeover</h2>
    {{if .Takeover}}
    <table>
      <thead><tr><th>#</th><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Vulnerable</th></tr></thead>
      <tbody>
      {{range $i,$t := .Takeover}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td>{{$t.Subdomain}}</td>
        <td class="mono">{{$t.CNAME}}</td>
        <td><span class="tag">{{$t.Service}}</span></td>
        <td>{{if $t.Vulnerable}}<span class="tag tag-alert">VULNERABLE</span>{{else}}<span class="tag">safe</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no subdomain takeover candidates found ]</p>{{end}}
  </div>

  <div id="tab-cors" class="tab-content">
    <h2>CORS Misconfiguration</h2>
    {{if .CORS}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Origin</th><th>ACAO</th><th>ACAC</th></tr></thead>
      <tbody>
      {{range $i,$c := .CORS}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td><a href="{{$c.URL}}" target="_blank">{{$c.URL}}</a></td>
        <td class="mono">{{$c.Origin}}</td>
        <td class="mono">{{$c.ACAO}}</td>
        <td class="mono">{{$c.ACAC}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no CORS issues found ]</p>{{end}}
  </div>

  <div id="tab-bypass" class="tab-content">
    <h2>403 Bypass</h2>
    {{if .Bypass}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Bypass URL</th><th>Technique</th><th>Status</th><th>Bypassed</th></tr></thead>
      <tbody>
      {{range $i,$b := .Bypass}}
      {{if $b.Bypassed}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$b.URL}}</td>
        <td class="mono">{{$b.BypassURL}}</td>
        <td><span class="tag tag-hi">{{$b.Technique}}</span></td>
        <td class="mono">{{$b.StatusCode}}</td>
        <td><span class="tag tag-alert">BYPASSED</span></td>
      </tr>
      {{end}}
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no 403 bypasses found ]</p>{{end}}
  </div>

  <div id="tab-vhosts" class="tab-content">
    <h2>Virtual Host Discovery</h2>
    {{if .VHosts}}
    <table>
      <thead><tr><th>#</th><th>IP</th><th>VHost</th><th>Status</th><th>Length</th></tr></thead>
      <tbody>
      {{range $i,$v := .VHosts}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$v.IP}}</td>
        <td style="color:var(--hi)">{{$v.VHost}}</td>
        <td class="mono">{{$v.Status}}</td>
        <td class="mono">{{$v.Length}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no virtual hosts discovered ]</p>{{end}}
  </div>

  <div id="tab-favicons" class="tab-content">
    <h2>Favicon Hash (Shodan MurmurHash3)</h2>
    {{if .Favicons}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>MurmurHash3</th></tr></thead>
      <tbody>
      {{range $i,$f := .Favicons}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td><a href="{{$f.URL}}" target="_blank">{{$f.URL}}</a></td>
        <td class="mono">{{$f.Hash}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no favicons found ]</p>{{end}}
  </div>

  <div id="tab-asn" class="tab-content">
    <h2>ASN Lookup</h2>
    {{if .ASN}}
    <table>
      <thead><tr><th>#</th><th>IP</th><th>ASN</th><th>BGP Prefix</th><th>Country</th><th>Org</th></tr></thead>
      <tbody>
      {{range $i,$a := .ASN}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$a.IP}}</td>
        <td><span class="tag tag-hi">{{$a.ASN}}</span></td>
        <td class="mono">{{$a.BGPPrefix}}</td>
        <td class="mono">{{$a.Country}}</td>
        <td class="mono">{{$a.Org}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no ASN data ]</p>{{end}}
  </div>

  <div id="tab-graphql" class="tab-content">
    <h2>GraphQL Endpoints</h2>
    {{if .GraphQL}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Endpoint</th><th>Introspection</th><th>Types</th></tr></thead>
      <tbody>
      {{range $i,$g := .GraphQL}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$g.URL}}</td>
        <td><a href="{{$g.Endpoint}}" target="_blank">{{$g.Endpoint}}</a></td>
        <td>{{if $g.Introspection}}<span class="tag tag-alert">ENABLED</span>{{else}}<span class="tag">disabled</span>{{end}}</td>
        <td>{{range $g.Types}}<span class="tag">{{.}}</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no GraphQL endpoints found ]</p>{{end}}
  </div>

  <div id="tab-emailsec" class="tab-content">
    <h2>Email Security (SPF / DMARC / DKIM)</h2>
    {{if .EmailSec}}
    <table>
      <tbody>
        <tr><td class="mono" style="width:160px;color:var(--dim)">Domain</td><td class="mono">{{.EmailSec.Domain}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">SPF</td><td class="mono">{{.EmailSec.SPF}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">SPF Strict</td><td class="mono">{{.EmailSec.SPFStrict}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">DMARC</td><td class="mono">{{.EmailSec.DMARC}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">DMARC Policy</td><td class="mono">{{.EmailSec.DMARCPolicy}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">DKIM</td><td class="mono">{{.EmailSec.DKIM}}</td></tr>
        <tr><td class="mono" style="color:var(--dim)">Spoofable</td><td class="mono">{{if .EmailSec.Spoofable}}<span class="tag tag-alert">YES</span>{{else}}<span class="tag tag-hi">NO</span>{{end}}</td></tr>
      </tbody>
    </table>
    {{else}}<p class="empty">[ email security check failed ]</p>{{end}}
  </div>

  <div id="tab-adminpanel" class="tab-content">
    <h2>Admin Panel Discovery</h2>
    {{if .AdminPanel}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Path</th><th>Status</th><th>Title</th></tr></thead>
      <tbody>
      {{range $i,$a := .AdminPanel}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$a.URL}}</td>
        <td style="color:var(--hi)">{{$a.Path}}</td>
        <td>
          {{if eq $a.StatusCode 200}}<span class="tag tag-hi">{{$a.StatusCode}}</span>
          {{else if eq $a.StatusCode 403}}<span class="tag tag-alert">{{$a.StatusCode}}</span>
          {{else if eq $a.StatusCode 401}}<span class="tag tag-alert">{{$a.StatusCode}}</span>
          {{else}}<span class="tag tag-warn">{{$a.StatusCode}}</span>{{end}}
        </td>
        <td class="mono">{{$a.Title}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no admin panels found ]</p>{{end}}
  </div>

  <div id="tab-sqli" class="tab-content">
    <h2>SQLi Detection</h2>
    {{if .SQLi}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th><th>Confidence</th></tr></thead>
      <tbody>
      {{range $i,$s := .SQLi}}
      {{if $s.Detected}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$s.URL}}</td>
        <td><span class="tag tag-alert">{{$s.Param}}</span></td>
        <td class="mono">{{$s.Payload}}</td>
        <td class="mono" style="color:var(--alert)">{{$s.Evidence}}</td>
        <td class="mono">{{$s.Confidence}}</td>
      </tr>
      {{end}}
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no SQLi indicators found ]</p>{{end}}
  </div>

  <div id="tab-defaultcreds" class="tab-content">
    <h2>Default Credentials</h2>
    {{if .DefaultCreds}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Username</th><th>Password</th><th>Status</th><th>Found</th></tr></thead>
      <tbody>
      {{range $i,$c := .DefaultCreds}}
      {{if $c.Found}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$c.URL}}</td>
        <td><span class="tag tag-alert">{{$c.Username}}</span></td>
        <td><span class="tag tag-alert">{{$c.Password}}</span></td>
        <td class="mono">{{$c.StatusCode}}</td>
        <td><span class="tag tag-alert">YES</span></td>
      </tr>
      {{end}}
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no default credentials found ]</p>{{end}}
  </div>

  <div id="tab-ratelimit" class="tab-content">
    <h2>Rate Limit Headers</h2>
    {{if .RateLimit}}
    <table>
      <thead><tr><th>#</th><th>URL</th><th>Header</th><th>Value</th></tr></thead>
      <tbody>
      {{range $i,$r := .RateLimit}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$r.URL}}</td>
        <td><span class="tag tag-hi">{{$r.Header}}</span></td>
        <td class="mono">{{$r.Value}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no rate limit headers detected ]</p>{{end}}
  </div>

  <div id="tab-templates" class="tab-content">
    <h2>Template Matches</h2>
    {{if .Templates}}
    <table>
      <thead><tr><th>#</th><th>ID</th><th>Name</th><th>Severity</th><th>URL</th><th>Matched</th></tr></thead>
      <tbody>
      {{range $i,$m := .Templates}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td class="mono">{{$m.TemplateID}}</td>
        <td>{{$m.Name}}</td>
        <td><span class="tag tag-hi">{{$m.Severity}}</span></td>
        <td class="mono">{{$m.URL}}</td>
        <td class="mono">{{$m.Matched}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">[ no template matches ]</p>{{end}}
  </div>

  <div id="tab-findings" class="tab-content">
{{if .Findings}}
<section id="findings">
<h2>Security Findings</h2>
<div class="findings-grid">
{{range .Findings}}
<div class="finding-card sev-{{.Severity}} conf-{{.Confidence}}">
  <div class="finding-header">
    <span class="badge sev-badge">{{upper .Severity}}</span>
    <span class="badge conf-badge">{{.Confidence}}</span>
    {{if .ManualVerification}}<span class="badge manual-badge">verify manually</span>{{end}}
    <span class="finding-type">{{.Type}}</span>
  </div>
  <div class="finding-title">{{.Title}}</div>
  <table class="finding-table">
    <tr><td class="fk">Affected</td><td class="fv">{{.AffectedURL}}</td></tr>
    <tr><td class="fk">Evidence</td><td class="fv"><code>{{.Evidence}}</code></td></tr>
    <tr><td class="fk">Reason</td><td class="fv">{{.Reason}}</td></tr>
    {{if .Remediation}}<tr><td class="fk">Fix</td><td class="fv">{{.Remediation}}</td></tr>{{end}}
    {{if .CVE}}<tr><td class="fk">CVE</td><td class="fv"><a href="{{index .References 0}}" target="_blank">{{.CVE}}</a> (CVSS {{.CVSS}})</td></tr>{{end}}
  </table>
</div>
{{end}}
</div>
</section>
{{else}}<p class="empty">[ no structured findings ]</p>{{end}}
  </div>

</div>

<footer>recon-x &nbsp;&middot;&nbsp; <a href="https://github.com/bytezora/recon-x">github.com/bytezora/recon-x</a> &nbsp;&middot;&nbsp; authorized testing only &nbsp;&middot;&nbsp; findings require manual verification</footer>

<script>
var currentTab = 'subdomains';
function show(tab, card) {
  document.querySelectorAll('.tab-content').forEach(function(el){el.classList.remove('active')});
  document.querySelectorAll('.card').forEach(function(el){el.classList.remove('active')});
  document.getElementById('tab-'+tab).classList.add('active');
  card.classList.add('active');
  currentTab = tab;
  var wrap = document.getElementById('search-wrap');
  var input = document.getElementById('search-input');
  var hasTable = document.querySelector('#tab-'+tab+' table');
  if(hasTable){wrap.classList.add('visible');}else{wrap.classList.remove('visible');}
  input.value='';
  filterTable('');
}
function filterTable(q) {
  var tab = document.getElementById('tab-'+currentTab);
  if(!tab) return;
  var rows = tab.querySelectorAll('tbody tr');
  var lower = q.toLowerCase();
  rows.forEach(function(row){
    row.style.display = (lower === '' || row.textContent.toLowerCase().indexOf(lower) > -1) ? '' : 'none';
  });
}
document.addEventListener('keydown', function(e) {
  if(e.key === '/' && document.activeElement.tagName !== 'INPUT') {
    e.preventDefault();
    document.getElementById('search-input').focus();
  }
  if(e.key === 'Escape') { document.getElementById('search-input').blur(); }
});
window.onload = function() {
  var firstCard = document.querySelector('.card');
  if(firstCard){ var wrap = document.getElementById('search-wrap'); var hasTable = document.querySelector('#tab-subdomains table'); if(hasTable) wrap.classList.add('visible'); }
};
</script>
</body>
</html>`

func Generate(
target string,
subs   []subdomain.Result,
ports  []portscan.Result,
http   []httpcheck.Result,
vs     []vulns.Match,
wafs   []waf.Result,
dirs   []dirbust.Hit,
jsf    []jsscan.Finding,
ghf    []ghsearch.Finding,
bkts   []buckets.Result,
tlsr   []tlscheck.Result,
redir  []openredirect.Result,
axfrr  []axfr.Result,
who    *whois.Result,
shots  []screenshot.Result,
tkover  []takeover.Result,
corsR   []cors.Result,
bypassR []bypass.Result,
vhosts  []vhost.Result,
favicons []favicon.Result,
asnR    []asn.Result,
gqlR    []graphql.Result,
emailR  *emailsec.Result,
adminPanel   []adminpanel.Result,
sqliRes      []sqli.Result,
defaultCreds []defaultcreds.Result,
rateLimit    []ratelimit.Result,
tplMatches   []templates.Match,
findings     []finding.Finding,
outputFile string,
) error {
f, err := os.Create(outputFile)
if err != nil {
return err
}
defer f.Close()

t := template.Must(template.New("r").Funcs(template.FuncMap{
	"upper": func(v interface{}) string { return strings.ToUpper(fmt.Sprintf("%s", v)) },
	"index": func(s []string, i int) string {
		if len(s) > i { return s[i] }
		return ""
	},
}).Parse(tmpl))
return t.Execute(f, Data{
Target:      target,
GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
Subdomains:  subs,
Ports:       ports,
HTTP:        http,
Vulns:       vs,
WAFs:        wafs,
DirHits:     dirs,
JSFindings:  jsf,
GHFindings:  ghf,
Buckets:     bkts,
TLS:         tlsr,
Redirects:   redir,
AXFR:        axfrr,
WHOIS:       who,
Screenshots: shots,
Takeover:  tkover,
CORS:      corsR,
Bypass:    bypassR,
VHosts:    vhosts,
Favicons:  favicons,
ASN:       asnR,
GraphQL:   gqlR,
EmailSec:    emailR,
AdminPanel:   adminPanel,
SQLi:         sqliRes,
DefaultCreds: defaultCreds,
RateLimit:    rateLimit,
Templates:    tplMatches,
Findings:     findings,
})
}
