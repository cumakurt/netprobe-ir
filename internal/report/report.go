package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"time"

	"netprobe-ir/internal/model"
)

type Data struct {
	GeneratedAt      time.Time               `json:"generated_at"`
	Status           model.Status            `json:"status"`
	Flows            []model.Flow            `json:"flows"`
	Alerts           []model.Alert           `json:"alerts"`
	SecurityFindings []model.SecurityFinding `json:"security_findings"`
	CaptureHealth    string                  `json:"capture_health"`
}

func JSON(d Data) ([]byte, error) { return json.MarshalIndent(d, "", "  ") }
func HTML(d Data) ([]byte, error) {
	const tpl = `<!doctype html><html><head><meta charset="utf-8"><title>NetProbe IR Security & Forensic Report</title><style>body{font:14px system-ui;margin:32px;color:#172033}h1{margin-bottom:4px}.muted{color:#667085}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}.card{border:1px solid #dfe5ec;border-radius:10px;padding:14px;background:#fff}table{width:100%;border-collapse:collapse;margin-top:12px;font-size:12px}th,td{text-align:left;padding:7px;border-bottom:1px solid #edf0f4;vertical-align:top}th{background:#f8fafc}.critical{color:#b42318;font-weight:800}.high{color:#c65f00;font-weight:700}.confirmed_ioc,.signature_match{font-weight:800}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><h1>NetProbe IR Security & Forensic Report</h1><div class="muted">Generated {{.GeneratedAt}} · Capture health: {{.CaptureHealth}}</div><div class="grid"><div class="card"><b>Packets</b><br>{{.Status.Packets}}</div><div class="card"><b>Bytes</b><br>{{.Status.Bytes}}</div><div class="card"><b>Flows</b><br>{{.Status.Flows}}</div><div class="card"><b>Processes</b><br>{{.Status.Processes}}</div><div class="card"><b>Security findings</b><br>{{.Status.SecurityFindings}}</div><div class="card"><b>Confirmed/signature</b><br>{{.Status.ConfirmedFindings}}</div></div><h2>Security Findings</h2><table><tr><th>Time</th><th>Severity</th><th>Verdict</th><th>Confidence</th><th>Rule</th><th>Finding</th><th>Source</th><th>Destination</th><th>Process</th><th>MITRE</th></tr>{{range .SecurityFindings}}<tr><td>{{.Time}}</td><td class="{{.Severity}}">{{.Severity}}</td><td class="{{.Verdict}}">{{.Verdict}}</td><td>{{.Confidence}}%</td><td class="mono">{{.RuleID}}</td><td>{{.Title}}<br><span class="muted">{{.Description}}</span></td><td class="mono">{{.Source.IP}}:{{.Source.Port}}</td><td class="mono">{{.Destination.IP}}:{{.Destination.Port}}</td><td>{{.Process}} {{if .PID}}({{.PID}}){{end}}</td><td>{{range .MITRE}}{{.}} {{end}}</td></tr>{{end}}</table><h2>Behavioral Alerts</h2><table><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Description</th><th>Process</th><th>Remote</th></tr>{{range .Alerts}}<tr><td>{{.Time}}</td><td class="{{.Severity}}">{{.Severity}}</td><td>{{.Rule}}</td><td>{{.Description}}</td><td>{{.Process}}</td><td>{{.Remote}}</td></tr>{{end}}</table><h2>Recent flows</h2><table><tr><th>Last seen</th><th>Process</th><th>Local</th><th>Remote</th><th>Protocol</th><th>TX</th><th>RX</th><th>Risk</th></tr>{{range .Flows}}<tr><td>{{.LastSeen}}</td><td>{{if .Process}}{{.Process.Comm}} ({{.Process.PID}}){{end}}</td><td class="mono">{{.Local.IP}}:{{.Local.Port}}</td><td class="mono">{{.Remote.IP}}:{{.Remote.Port}}</td><td>{{.DPI.Protocol}}</td><td>{{.BytesTX}}</td><td>{{.BytesRX}}</td><td>{{.Risk}}</td></tr>{{end}}</table><hr><div class="muted">NetProbe IR · Developer: Cuma KURT &lt;cumakurt@gmail.com&gt; · Repository: https://github.com/cumakurt/netprobe-ir · GNU GPLv3</div></body></html>`
	t, err := template.New("r").Parse(tpl)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, d); err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	return b.Bytes(), nil
}
