package pipeline

import (
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

func (e *Engine) recordAccess(p *decode.Packet, f model.Flow, observations []model.DPIInfo, created bool) {
	if e.AccessLog == nil {
		return
	}
	add := func(kind string, di model.DPIInfo) {
		entry := model.PacketSummary{Time: p.Time, Interface: p.Interface, Direction: p.Direction, NetworkProtocol: p.Protocol, Source: model.Endpoint{IP: p.SrcIP, Port: p.SrcPort}, Destination: model.Endpoint{IP: p.DstIP, Port: p.DstPort}, FlowID: f.ID, DPI: di, Process: f.Process, Length: len(p.Raw)}
		e.AccessLog.Add(kind, entry)
	}
	for _, di := range observations {
		if di.DNS != nil {
			add("dns", di)
		} else if di.HTTP != nil {
			add("http", di)
		} else if di.TLS != nil {
			add("tls", di)
		} else if di.HTTP2 != nil {
			add("http2", di)
		}
	}
	// Connection observations are explicitly distinct from HTTP requests.
	if created && (f.DPI.Encrypted && (p.SrcPort == 443 || p.DstPort == 443)) {
		add("connection", f.DPI)
	}
}
