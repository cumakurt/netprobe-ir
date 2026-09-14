// readme-demo serves the real console with documentation-only synthetic evidence.
// Run it only on loopback in an isolated network namespace.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/cases"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/detectionquality"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
	"netprobe-ir/internal/procmap"
	"netprobe-ir/internal/server"
	"netprobe-ir/internal/triage"
)

type demoFlow struct {
	local, remote         string
	localPort, remotePort uint16
	protocol, process     string
	pid                   int
	payload               []byte
}

var flows = []demoFlow{
	{"10.42.0.17", "203.0.113.77", 51123, 80, "TCP", "python3", 61001, []byte("GET /update/check HTTP/1.1\r\nHost: updates.example.test\r\nUser-Agent: demo-agent\r\n\r\n")},
	{"10.42.0.17", "198.51.100.42", 51124, 443, "TCP", "curl", 61002, clientHello("login.example.test")},
	{"10.42.0.24", "192.0.2.22", 51125, 22, "TCP", "ssh", 61003, []byte("SSH-2.0-OpenSSH_9.6\r\n")},
	{"10.42.0.17", "192.0.2.53", 53000, 53, "UDP", "systemd-resolved", 61004, dnsQuery("updates.example.test")},
	{"10.42.0.24", "203.0.113.80", 51126, 80, "TCP", "firefox", 61005, []byte("GET /dashboard HTTP/1.1\r\nHost: portal.example.test\r\n\r\n")},
	{"10.42.0.31", "198.51.100.50", 53001, 443, "UDP", "browser", 61006, []byte{0xc0, 0, 0, 0, 1, 4, 0xde, 0xad, 0xbe, 0xef, 4, 1, 2, 3, 4, 0, 17, 0, 0, 0, 0}},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:19003", "loopback console address")
	dataDir := flag.String("data-dir", "", "isolated demo data directory")
	flag.Parse()
	if *dataDir == "" {
		log.Fatal("--data-dir is required")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("demo listener must use a numeric loopback address")
	}
	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		log.Fatal(err)
	}
	c := config.Default()
	c.DataDir = *dataDir
	c.Listen = *listen
	c.Interfaces = []string{"demo0"}
	c.Auth.Enabled = false
	c.Recorder.Enabled = false
	c.Attribution.Backend = "proc"
	c.ThreatIntel.Enabled = false
	c.SelfProtection.Enabled = false
	if err := c.Prepare(); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e := pipeline.New(c)
	if err := e.Start(ctx); err != nil {
		log.Fatal(err)
	}
	if err := seed(e); err != nil {
		log.Fatal(err)
	}
	go stream(ctx, e)
	srv := &http.Server{Addr: *listen, Handler: server.New(e, "").Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("Synthetic README console listening on %s; data in %s", *listen, filepath.Clean(*dataDir))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func seed(e *pipeline.Engine) error {
	now := time.Now().UTC()
	for _, spec := range flows {
		e.Proc.AddKernelEvent(procmap.KernelEvent{Proto: spec.protocol, LocalIP: spec.local, LocalPort: spec.localPort, RemoteIP: spec.remote, RemotePort: spec.remotePort, PID: spec.pid, Comm: spec.process, Time: now})
		if spec.protocol == "TCP" {
			e.ProcessFrame(frame(spec, now, 0x02, nil))
		}
		e.ProcessFrame(frame(spec, now.Add(time.Millisecond), 0x18, spec.payload))
	}
	indexed := map[string]model.Flow{}
	for _, f := range e.VisibleFlows(0) {
		indexed[fmt.Sprintf("%s:%d", f.Remote.IP, f.Remote.Port)] = f
	}
	var findings []model.SecurityFinding
	definitions := []struct {
		flow                                                  int
		id, title, severity, verdict, category, tactic, mitre string
		confidence, risk                                      int
	}{
		{0, "DEMO-IOC-001", "Known command-and-control endpoint contacted", "critical", "confirmed_ioc", "command_and_control", "Command and Control", "T1071.001", 98, 94},
		{0, "DEMO-PERSIST-002", "Unusual startup process contacted external host", "high", "behavioral", "persistence", "Persistence", "T1543.002", 83, 86},
		{1, "DEMO-TLS-003", "Repeated encrypted sessions to uncommon peer", "high", "behavioral", "command_and_control", "Command and Control", "T1573", 77, 74},
		{3, "DEMO-DNS-004", "Rare domain queried by workstation", "medium", "behavioral", "discovery", "Discovery", "T1018", 71, 51},
		{4, "DEMO-WEB-005", "Web access to newly observed destination", "medium", "signature_match", "web", "Initial Access", "T1189", 91, 58},
	}
	for i, item := range definitions {
		spec := flows[item.flow]
		f, ok := indexed[fmt.Sprintf("%s:%d", spec.remote, spec.remotePort)]
		if !ok {
			return fmt.Errorf("missing synthetic flow for %s", spec.remote)
		}
		finding := model.SecurityFinding{
			ID:          item.id,
			Time:        now.Add(time.Duration(i) * time.Second),
			Severity:    item.severity,
			Confidence:  item.confidence,
			Verdict:     item.verdict,
			RuleID:      item.id,
			Title:       item.title,
			Description: "Synthetic documentation fixture; no live incident or external host is involved.",
			Category:    item.category,
			Tactic:      item.tactic,
			MITRE:       []string{item.mitre},
			Tags:        []string{"demo", "synthetic"},
			FlowID:      f.ID,
			Interface:   "demo0",
			Direction:   model.DirectionOutbound,
			Source:      model.Endpoint{IP: spec.local, Port: spec.localPort},
			Destination: model.Endpoint{IP: spec.remote, Port: spec.remotePort},
			Protocol:    spec.protocol,
			Application: f.DPI.Application,
			PID:         spec.pid,
			Process:     spec.process,
		}
		e.IDS.AddFinding(finding)
		e.Store.SetRisk(f.ID, item.risk, []string{"Synthetic documentation finding"})
		findings = append(findings, finding)
	}
	if err := seedCase(e, indexed, findings, now); err != nil {
		return err
	}
	for i, run := range []detectionquality.Run{
		{Label: "synthetic-positive-01", ExpectedRules: []string{"DEMO-IOC-001", "DEMO-TLS-003"}, Observed: map[string]int{"DEMO-IOC-001": 1, "DEMO-TLS-003": 1}, Frames: 900, ElapsedMS: 35},
		{Label: "synthetic-positive-02", ExpectedRules: []string{"DEMO-IOC-001", "DEMO-DNS-004"}, Observed: map[string]int{"DEMO-IOC-001": 1}, Frames: 1100, ElapsedMS: 42},
		{Label: "synthetic-benign-01", Benign: true, Observed: map[string]int{}, Frames: 800, ElapsedMS: 29},
		{Label: "synthetic-benign-02", Benign: true, Observed: map[string]int{"DEMO-TLS-003": 1}, Frames: 750, ElapsedMS: 30},
	} {
		run.Time = now.Add(time.Duration(i) * time.Second)
		if err := e.RecordDetectionQuality(run); err != nil {
			return err
		}
	}
	return nil
}

func seedCase(e *pipeline.Engine, indexed map[string]model.Flow, findings []model.SecurityFinding, now time.Time) error {
	f := indexed["203.0.113.77:80"]
	if latest, ok := e.Store.Get(f.ID); ok {
		f = latest
	}
	packets := make([]model.PacketSummary, 0, 2)
	for _, p := range e.VisiblePackets(0) {
		if p.FlowID == f.ID && len(packets) < 2 {
			packets = append(packets, p)
		}
	}
	incident := cases.Case{
		ID:         "DEMO-IR-001",
		Title:      "Demo: suspicious outbound activity from workstation-17",
		Severity:   "critical",
		Findings:   findings[:2],
		Flows:      []model.Flow{f},
		Packets:    packets,
		FindingIDs: []string{findings[0].ID, findings[1].ID},
		FlowIDs:    []string{f.ID},
		Tags:       []string{"synthetic", "triage", "network"},
		Notes:      []cases.Note{{Time: now, Author: "demo-analyst", Text: "Synthetic evidence prepared for the README product tour."}},
	}
	if _, err := e.Cases.Create(incident); err != nil {
		return err
	}
	begin, end := now.Add(-5*time.Minute), now.Add(5*time.Minute)
	snapshot := triage.Snapshot{
		CollectedAt: now,
		CollectedBy: "demo-analyst",
		Hostname:    "workstation-17.example.test",
		FindingID:   findings[0].ID,
		Process: triage.Process{
			PID: 61001, PPID: 61000, UID: 1000, Comm: "python3", Exe: "/usr/bin/python3",
			ExeSHA256: strings.Repeat("a", 64), ExeSize: 6839896, StartTimeTicks: 123456789,
		},
		Ancestors: []triage.Process{
			{PID: 61000, PPID: 1, Comm: "systemd", Exe: "/usr/lib/systemd/systemd"},
		},
		Connections: []triage.Connection{
			{Protocol: "TCP", Local: "10.42.0.17:51123", Remote: "203.0.113.77:80", State: "ESTABLISHED", SocketInode: "1234567"},
		},
		OpenFiles: []triage.OpenFile{
			{FD: 4, Path: "/home/demo/.cache/agent.py", Size: 24819, ModifiedAt: now.Add(-time.Hour), Inode: "2345678"},
		},
		Persistence: []triage.PersistenceArtifact{
			{Scope: "host", Path: "/etc/systemd/system/demo-agent.service", Kind: "systemd-unit", ModifiedAt: now.Add(-2 * time.Hour), SHA256: strings.Repeat("b", 64)},
		},
		JournalWindowStart: &begin,
		JournalWindowEnd:   &end,
		Journal: []triage.JournalEntry{
			{Time: now, Unit: "demo-agent.service", Identifier: "python3", Priority: "warning", MessageBytes: 127, MessageSHA256: strings.Repeat("c", 64)},
		},
	}
	_, err := e.Cases.AddTriage(incident.ID, snapshot)
	return err
}

func stream(ctx context.Context, e *pipeline.Engine) {
	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			for _, spec := range flows {
				e.ProcessFrame(frame(spec, now.UTC(), 0x18, spec.payload))
			}
		case <-ctx.Done():
			return
		}
	}
}

func frame(spec demoFlow, at time.Time, flags byte, payload []byte) capture.Frame {
	transport := 20
	protocol := byte(6)
	if spec.protocol == "UDP" {
		transport = 8
		protocol = 17
	}
	length := 20 + transport + len(payload)
	b := make([]byte, 14+length)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(length))
	ip[8] = 64
	ip[9] = protocol
	copy(ip[12:16], net.ParseIP(spec.local).To4())
	copy(ip[16:20], net.ParseIP(spec.remote).To4())
	l4 := ip[20:]
	binary.BigEndian.PutUint16(l4[0:2], spec.localPort)
	binary.BigEndian.PutUint16(l4[2:4], spec.remotePort)
	if spec.protocol == "TCP" {
		binary.BigEndian.PutUint32(l4[4:8], 100)
		l4[12] = 0x50
		l4[13] = flags
	} else {
		binary.BigEndian.PutUint16(l4[4:6], uint16(transport+len(payload)))
	}
	copy(l4[transport:], payload)
	return capture.Frame{Time: at, Interface: "demo0", Direction: model.DirectionOutbound, Data: b}
}

func dnsQuery(name string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 0x1221)
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

func clientHello(name string) []byte {
	sni := []byte(name)
	serverName := make([]byte, 5+len(sni))
	binary.BigEndian.PutUint16(serverName[:2], uint16(3+len(sni)))
	binary.BigEndian.PutUint16(serverName[3:5], uint16(len(sni)))
	copy(serverName[5:], sni)
	ext := appendExtension(nil, 0, serverName)
	ext = appendExtension(ext, 16, []byte{0, 3, 2, 'h', '2'})
	ext = appendExtension(ext, 43, []byte{2, 3, 4})
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 4, 0x13, 1, 0x13, 2, 1, 0)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(ext)))
	body = append(body, length...)
	body = append(body, ext...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	return append(record, handshake...)
}

func appendExtension(dst []byte, kind uint16, value []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[:2], kind)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(value)))
	dst = append(dst, header...)
	return append(dst, value...)
}
