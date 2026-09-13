package investigation

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"netprobe-ir/internal/model"
)

type Node struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Label string         `json:"label"`
	Risk  int            `json:"risk,omitempty"`
	Meta  map[string]any `json:"meta,omitempty"`
}
type Edge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Type   string `json:"type"`
	Label  string `json:"label,omitempty"`
	Weight uint64 `json:"weight,omitempty"`
}
type Graph struct {
	Nodes []Node    `json:"nodes"`
	Edges []Edge    `json:"edges"`
	Meta  GraphMeta `json:"meta,omitempty"`
}

func Build(flows []model.Flow, findings []model.SecurityFinding, limit int) Graph {
	return BuildExtended(flows, findings, nil, limit)
}

func BuildExtended(flows []model.Flow, findings []model.SecurityFinding, files []model.FileArtifact, limit int) Graph {
	if limit <= 0 {
		limit = 500
	}
	if len(flows) > limit {
		flows = flows[:limit]
	}
	nodes := map[string]Node{}
	edges := map[string]Edge{}
	addN := func(n Node) {
		if old, ok := nodes[n.ID]; ok {
			if n.Risk > old.Risk {
				old.Risk = n.Risk
			}
			nodes[n.ID] = old
		} else {
			nodes[n.ID] = n
		}
	}
	addE := func(e Edge) {
		k := e.From + "|" + e.To + "|" + e.Type
		if old, ok := edges[k]; ok {
			old.Weight += e.Weight
			edges[k] = old
		} else {
			edges[k] = e
		}
	}
	for _, f := range flows {
		flowID := "flow:" + f.ID
		addN(Node{ID: flowID, Type: "flow", Label: fmt.Sprintf("%s %s:%d", f.NetworkProtocol, f.Remote.IP, f.Remote.Port), Risk: f.Risk, Meta: map[string]any{"flow_id": f.ID}})
		local := "ip:" + f.Local.IP
		remote := "ip:" + f.Remote.IP
		addN(Node{ID: local, Type: "ip", Label: f.Local.IP})
		addN(Node{ID: remote, Type: "ip", Label: f.Remote.IP, Risk: f.Risk})
		addE(Edge{From: local, To: flowID, Type: "source", Weight: f.BytesTX})
		addE(Edge{From: flowID, To: remote, Type: "destination", Weight: f.BytesRX})
		if f.Process != nil {
			pid := fmt.Sprintf("process:%d", f.Process.PID)
			label := f.Process.Comm
			if label == "" {
				label = f.Process.Exe
			}
			addN(Node{ID: pid, Type: "process", Label: label, Risk: f.Risk, Meta: map[string]any{"pid": f.Process.PID, "exe": f.Process.Exe}})
			addE(Edge{From: pid, To: flowID, Type: "opened", Weight: f.BytesTX + f.BytesRX})
		}
		for _, iface := range f.Interfaces {
			id := "iface:" + iface
			addN(Node{ID: id, Type: "interface", Label: iface})
			addE(Edge{From: id, To: flowID, Type: "observed"})
		}
		if f.DPI.DNS != nil && f.DPI.DNS.Query != "" {
			d := "domain:" + strings.ToLower(f.DPI.DNS.Query)
			addN(Node{ID: d, Type: "domain", Label: f.DPI.DNS.Query, Risk: f.Risk})
			addE(Edge{From: flowID, To: d, Type: "dns"})
		}
		if f.DPI.TLS != nil {
			if f.DPI.TLS.SNI != "" {
				d := "domain:" + strings.ToLower(f.DPI.TLS.SNI)
				addN(Node{ID: d, Type: "domain", Label: f.DPI.TLS.SNI, Risk: f.Risk})
				addE(Edge{From: flowID, To: d, Type: "sni"})
			}
			if f.DPI.TLS.JA4 != "" {
				j := "ja4:" + f.DPI.TLS.JA4
				addN(Node{ID: j, Type: "tls", Label: f.DPI.TLS.JA4})
				addE(Edge{From: flowID, To: j, Type: "tls-fingerprint"})
			}
		}
	}
	// Enrich the graph with process ancestry observed on flows. Parent nodes are
	// explicit even when the parent itself has not opened a retained network flow.
	for _, f := range flows {
		if f.Process == nil || f.Process.PID <= 0 || f.Process.PPID <= 0 {
			continue
		}
		child := fmt.Sprintf("process:%d", f.Process.PID)
		parent := fmt.Sprintf("process:%d", f.Process.PPID)
		addN(Node{ID: parent, Type: "process", Label: fmt.Sprintf("PID %d", f.Process.PPID), Meta: map[string]any{"pid": f.Process.PPID}})
		addE(Edge{From: parent, To: child, Type: "parent-of"})
	}
	for _, a := range files {
		id := "file:" + a.ID
		addN(Node{ID: id, Type: "file", Label: a.Name, Risk: fileRisk(a), Meta: map[string]any{"file_id": a.ID, "sha256": a.SHA256, "mime": a.MIME, "size": a.Size, "entropy": a.Entropy}})
		if a.FlowID != "" {
			addE(Edge{From: "flow:" + a.FlowID, To: id, Type: "transferred-file", Weight: uint64(max64(a.Size, 0))})
		}
		if a.Process != nil && a.Process.PID > 0 {
			addE(Edge{From: fmt.Sprintf("process:%d", a.Process.PID), To: id, Type: "file-transfer"})
		}
		if a.SHA256 != "" {
			h := "sha256:" + a.SHA256
			addN(Node{ID: h, Type: "hash", Label: a.SHA256})
			addE(Edge{From: id, To: h, Type: "hash"})
		}
		for _, y := range a.Yara {
			yid := "yara:" + y.Rule
			addN(Node{ID: yid, Type: "yara", Label: y.Rule, Risk: 100})
			addE(Edge{From: id, To: yid, Type: "yara-match"})
		}
	}
	for _, f := range findings {
		id := "finding:" + f.ID
		addN(Node{ID: id, Type: "finding", Label: f.RuleID + " · " + f.Title, Risk: severityRisk(f.Severity), Meta: map[string]any{"finding_id": f.ID, "verdict": f.Verdict, "confidence": f.Confidence}})
		if f.FlowID != "" {
			addE(Edge{From: id, To: "flow:" + f.FlowID, Type: "evidence"})
		}
		if f.PID > 0 {
			addE(Edge{From: id, To: fmt.Sprintf("process:%d", f.PID), Type: "process"})
		}
	}
	g := Graph{}
	for _, n := range nodes {
		g.Nodes = append(g.Nodes, n)
	}
	for _, e := range edges {
		g.Edges = append(g.Edges, e)
	}
	sort.Slice(g.Nodes, func(i, j int) bool {
		if g.Nodes[i].Risk != g.Nodes[j].Risk {
			return g.Nodes[i].Risk > g.Nodes[j].Risk
		}
		return g.Nodes[i].ID < g.Nodes[j].ID
	})
	sort.Slice(g.Edges, func(i, j int) bool { return g.Edges[i].From+g.Edges[i].To < g.Edges[j].From+g.Edges[j].To })
	return g
}
func fileRisk(a model.FileArtifact) int {
	if len(a.Yara) > 0 {
		return 100
	}
	if a.Entropy >= 7.5 {
		return 70
	}
	return 20
}
func max64(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func severityRisk(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 100
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 30
	default:
		return 10
	}
}

type Query struct {
	Search           string
	SourceIP         string
	DestinationIP    string
	Asset            string
	Protocol         string
	Port             uint16
	Application      string
	Severity         string
	From             time.Time
	To               time.Time
	FocusID          string
	Neighborhood     int
	MaxNodes         int
	MaxEdges         int
	EnableClustering bool
	ExpandCluster    string
}

type GraphMeta struct {
	FilteredFlows    int  `json:"filtered_flows"`
	FilteredFindings int  `json:"filtered_findings"`
	TotalNodes       int  `json:"total_nodes"`
	TotalEdges       int  `json:"total_edges"`
	VisibleNodes     int  `json:"visible_nodes"`
	VisibleEdges     int  `json:"visible_edges"`
	Clustered        bool `json:"clustered"`
	Truncated        bool `json:"truncated"`
	MaxNodes         int  `json:"max_nodes"`
	MaxEdges         int  `json:"max_edges"`
}

func BuildQuery(flows []model.Flow, findings []model.SecurityFinding, files []model.FileArtifact, q Query) Graph {
	if q.MaxNodes <= 0 {
		q.MaxNodes = 800
	}
	if q.MaxNodes > 2000 {
		q.MaxNodes = 2000
	}
	if q.MaxEdges <= 0 {
		q.MaxEdges = 3000
	}
	if q.MaxEdges > 10000 {
		q.MaxEdges = 10000
	}
	if q.Neighborhood <= 0 {
		q.Neighborhood = 1
	}
	filteredFlows := make([]model.Flow, 0, len(flows))
	flowIDs := map[string]bool{}
	for _, f := range flows {
		if matchFlow(f, q) {
			filteredFlows = append(filteredFlows, f)
			flowIDs[f.ID] = true
		}
	}
	filteredFindings := make([]model.SecurityFinding, 0, len(findings))
	for _, f := range findings {
		if !matchFinding(f, q) {
			continue
		}
		if f.FlowID != "" && len(flowIDs) > 0 && !flowIDs[f.FlowID] && (q.SourceIP != "" || q.DestinationIP != "" || q.Asset != "" || q.Protocol != "" || q.Port > 0 || q.Application != "") {
			continue
		}
		filteredFindings = append(filteredFindings, f)
	}
	filteredFiles := make([]model.FileArtifact, 0, len(files))
	for _, a := range files {
		if a.FlowID == "" || flowIDs[a.FlowID] {
			filteredFiles = append(filteredFiles, a)
		}
	}
	g := BuildExtended(filteredFlows, filteredFindings, filteredFiles, maxInt(len(filteredFlows), 1))
	totalNodes, totalEdges := len(g.Nodes), len(g.Edges)
	if q.FocusID != "" {
		g = neighborhood(g, q.FocusID, q.Neighborhood)
	}
	clustered := false
	if q.EnableClustering && len(g.Nodes) > q.MaxNodes {
		g = clusterGraph(g, q.MaxNodes, q.ExpandCluster)
		clustered = true
	}
	truncated := false
	if len(g.Nodes) > q.MaxNodes {
		g.Nodes = g.Nodes[:q.MaxNodes]
		truncated = true
	}
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	edges := make([]Edge, 0, minInt(len(g.Edges), q.MaxEdges))
	for _, e := range g.Edges {
		if ids[e.From] && ids[e.To] {
			edges = append(edges, e)
			if len(edges) >= q.MaxEdges {
				truncated = true
				break
			}
		}
	}
	g.Edges = edges
	g.Meta = GraphMeta{FilteredFlows: len(filteredFlows), FilteredFindings: len(filteredFindings), TotalNodes: totalNodes, TotalEdges: totalEdges, VisibleNodes: len(g.Nodes), VisibleEdges: len(g.Edges), Clustered: clustered, Truncated: truncated, MaxNodes: q.MaxNodes, MaxEdges: q.MaxEdges}
	return g
}

func matchFlow(f model.Flow, q Query) bool {
	if !q.From.IsZero() && f.LastSeen.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && f.FirstSeen.After(q.To) {
		return false
	}
	src, dst := flowEndpoints(f)
	if q.SourceIP != "" && src.IP != q.SourceIP {
		return false
	}
	if q.DestinationIP != "" && dst.IP != q.DestinationIP {
		return false
	}
	if q.Protocol != "" && !strings.Contains(strings.ToLower(f.NetworkProtocol+" "+f.DPI.Protocol), strings.ToLower(q.Protocol)) {
		return false
	}
	if q.Port > 0 && src.Port != q.Port && dst.Port != q.Port {
		return false
	}
	if q.Application != "" && !strings.Contains(strings.ToLower(f.DPI.Application+" "+f.DPI.Protocol), strings.ToLower(q.Application)) {
		return false
	}
	if q.Asset != "" {
		a := strings.ToLower(q.Asset)
		hay := strings.ToLower(f.Local.IP + " " + f.Remote.IP + " " + strings.Join(f.Interfaces, " ") + " " + f.DPI.Application + " " + f.DPI.Protocol)
		if f.Process != nil {
			hay += " " + strings.ToLower(f.Process.Comm+" "+f.Process.Exe+" "+f.Process.User+" "+f.Process.ContainerID+" "+f.Process.KubernetesPod)
		}
		if f.DPI.TLS != nil {
			hay += " " + strings.ToLower(f.DPI.TLS.SNI)
		}
		if f.DPI.DNS != nil {
			hay += " " + strings.ToLower(f.DPI.DNS.Query)
		}
		if !strings.Contains(hay, a) {
			return false
		}
	}
	if q.Search != "" {
		x := strings.ToLower(q.Search)
		hay := strings.ToLower(f.ID + " " + f.Local.IP + " " + f.Remote.IP + " " + f.NetworkProtocol + " " + f.DPI.Protocol + " " + f.DPI.Application)
		if f.Process != nil {
			hay += " " + strings.ToLower(f.Process.Comm+" "+f.Process.Exe)
		}
		if !strings.Contains(hay, x) {
			return false
		}
	}
	return true
}
func matchFinding(f model.SecurityFinding, q Query) bool {
	if q.Severity != "" && !strings.EqualFold(f.Severity, q.Severity) {
		return false
	}
	if q.SourceIP != "" && f.Source.IP != q.SourceIP {
		return false
	}
	if q.DestinationIP != "" && f.Destination.IP != q.DestinationIP {
		return false
	}
	if q.Port > 0 && f.Source.Port != q.Port && f.Destination.Port != q.Port {
		return false
	}
	if q.Protocol != "" && !strings.Contains(strings.ToLower(f.Protocol), strings.ToLower(q.Protocol)) {
		return false
	}
	if q.Application != "" && !strings.Contains(strings.ToLower(f.Application), strings.ToLower(q.Application)) {
		return false
	}
	if q.Asset != "" {
		a := strings.ToLower(q.Asset)
		hay := strings.ToLower(f.Source.IP + " " + f.Destination.IP + " " + f.Process + " " + f.Interface + " " + f.Application + " " + f.Protocol)
		if !strings.Contains(hay, a) {
			return false
		}
	}
	if !q.From.IsZero() && f.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && f.Time.After(q.To) {
		return false
	}
	if q.Search != "" && !strings.Contains(strings.ToLower(f.RuleID+" "+f.Title+" "+f.Description+" "+f.Source.IP+" "+f.Destination.IP+" "+f.Process), strings.ToLower(q.Search)) {
		return false
	}
	return true
}
func flowEndpoints(f model.Flow) (model.Endpoint, model.Endpoint) {
	if f.Direction == model.DirectionInbound {
		return f.Remote, f.Local
	}
	return f.Local, f.Remote
}
func neighborhood(g Graph, focus string, depth int) Graph {
	if depth < 1 {
		depth = 1
	}
	adj := map[string][]string{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	keep := map[string]bool{focus: true}
	front := []string{focus}
	for d := 0; d < depth; d++ {
		next := []string{}
		for _, x := range front {
			for _, y := range adj[x] {
				if !keep[y] {
					keep[y] = true
					next = append(next, y)
				}
			}
		}
		front = next
	}
	out := Graph{}
	for _, n := range g.Nodes {
		if keep[n.ID] {
			out.Nodes = append(out.Nodes, n)
		}
	}
	for _, e := range g.Edges {
		if keep[e.From] && keep[e.To] {
			out.Edges = append(out.Edges, e)
		}
	}
	return out
}
func clusterKey(n Node) string {
	switch n.Type {
	case "ip":
		if ip := net.ParseIP(n.Label); ip != nil {
			if ip.IsPrivate() {
				return "private-ip"
			}
			return "internet"
		}
		return "ip"
	case "flow":
		return "flows"
	case "domain":
		return "domains"
	case "tls":
		return "tls"
	case "interface":
		return "interfaces"
	case "file", "hash", "yara":
		return "files"
	default:
		return n.Type
	}
}
func clusterGraph(g Graph, maxNodes int, expand string) Graph {
	important := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Risk >= 80 || n.Type == "finding" || n.ID == expand {
			important[n.ID] = true
		}
	}
	groups := map[string][]Node{}
	for _, n := range g.Nodes {
		k := clusterKey(n)
		if important[n.ID] || k == expand {
			groups[n.ID] = []Node{n}
		} else {
			groups[k] = append(groups[k], n)
		}
	}
	mapID := map[string]string{}
	out := Graph{}
	for k, xs := range groups {
		if len(xs) == 1 && (important[xs[0].ID] || k == xs[0].ID || k == expand) {
			out.Nodes = append(out.Nodes, xs[0])
			mapID[xs[0].ID] = xs[0].ID
			continue
		}
		cid := "cluster:" + k
		members := make([]string, 0, minInt(len(xs), 100))
		risk := 0
		for _, n := range xs {
			mapID[n.ID] = cid
			if len(members) < 100 {
				members = append(members, n.ID)
			}
			if n.Risk > risk {
				risk = n.Risk
			}
		}
		out.Nodes = append(out.Nodes, Node{ID: cid, Type: "cluster", Label: clusterLabel(k, len(xs)), Risk: risk, Meta: map[string]any{"cluster": true, "cluster_key": k, "count": len(xs), "member_ids": members}})
	}
	em := map[string]Edge{}
	for _, e := range g.Edges {
		a, b := mapID[e.From], mapID[e.To]
		if a == "" {
			a = e.From
		}
		if b == "" {
			b = e.To
		}
		if a == b {
			continue
		}
		key := a + "|" + b + "|" + e.Type
		x := em[key]
		x.From = a
		x.To = b
		x.Type = e.Type
		x.Weight += maxUint64(e.Weight, 1)
		em[key] = x
	}
	for _, e := range em {
		out.Edges = append(out.Edges, e)
	}
	sort.Slice(out.Nodes, func(i, j int) bool {
		return out.Nodes[i].Risk > out.Nodes[j].Risk || out.Nodes[i].Risk == out.Nodes[j].Risk && out.Nodes[i].ID < out.Nodes[j].ID
	})
	sort.Slice(out.Edges, func(i, j int) bool { return out.Edges[i].Weight > out.Edges[j].Weight })
	if len(out.Nodes) > maxNodes {
		out.Nodes = out.Nodes[:maxNodes]
	}
	return out
}
func clusterLabel(k string, n int) string {
	names := map[string]string{"private-ip": "Private hosts", "internet": "Internet", "flows": "Flows", "domains": "Domains", "process": "Processes", "interfaces": "Interfaces", "tls": "TLS fingerprints", "files": "Files / hashes", "ip": "IP hosts"}
	name := names[k]
	if name == "" {
		name = strings.Title(strings.ReplaceAll(k, "_", " "))
	}
	return fmt.Sprintf("%s (%d)", name, n)
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
