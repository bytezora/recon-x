package report

import (
"html/template"
"os"
"time"

"github.com/bytezora/recon-x/internal/dirbust"
"github.com/bytezora/recon-x/internal/httpcheck"
"github.com/bytezora/recon-x/internal/jsscan"
"github.com/bytezora/recon-x/internal/portscan"
"github.com/bytezora/recon-x/internal/subdomain"
"github.com/bytezora/recon-x/internal/vulns"
"github.com/bytezora/recon-x/internal/waf"
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
  grid-template-columns:repeat(7,1fr);
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

/* ── footer ── */
footer{
  text-align:center;
  padding:.7rem;
  color:var(--dim);
  font-size:.68rem;
  border-top:1px solid var(--line);
  flex-shrink:0;
  letter-spacing:1px;
}
</style>
</head>
<body>

<header>
  <span class="logo">RECON-X</span>
  <span class="logo-sep">//</span>
  <span class="target">{{.Target}}</span>
  <span class="meta">{{.GeneratedAt}}</span>
</header>

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
      <thead><tr><th>#</th><th>Host</th><th>Port</th><th>CVE</th><th>CVSS</th><th>Severity</th><th>Description</th><th>Banner / Header</th></tr></thead>
      <tbody>
      {{range $i,$v := .Vulns}}
      <tr>
        <td class="mono">{{$i}}</td>
        <td>{{$v.Host}}</td>
        <td>{{if $v.Port}}<span class="tag tag-hi">{{$v.Port}}</span>{{else}}<span class="tag">HTTP</span>{{end}}</td>
        <td><a href="{{$v.Link}}" target="_blank">{{$v.CVE}}</a></td>
        <td class="mono">{{printf "%.1f" $v.CVSS}}</td>
        <td>
          {{if eq $v.Severity "CRITICAL"}}<span class="sev-crit">CRITICAL</span>
          {{else if eq $v.Severity "HIGH"}}<span class="sev-high">HIGH</span>
          {{else}}<span class="sev-med">{{$v.Severity}}</span>{{end}}
        </td>
        <td>{{$v.Description}}</td>
        <td class="mono">{{$v.Banner}}</td>
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

</div>

<footer>recon-x v1.2.1 &nbsp;&middot;&nbsp; <a href="https://github.com/bytezora/recon-x">github.com/bytezora/recon-x</a> &nbsp;&middot;&nbsp; authorized testing only</footer>

<script>
function show(tab, card) {
  document.querySelectorAll('.tab-content').forEach(function(el){el.classList.remove('active')});
  document.querySelectorAll('.card').forEach(function(el){el.classList.remove('active')});
  document.getElementById('tab-'+tab).classList.add('active');
  card.classList.add('active');
}
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
outputFile string,
) error {
f, err := os.Create(outputFile)
if err != nil {
return err
}
defer f.Close()

t := template.Must(template.New("report").Parse(tmpl))
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
})
}
