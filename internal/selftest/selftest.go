package selftest

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"netprobe-ir/internal/anomaly"
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/dpi"
	"netprobe-ir/internal/flow"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pcapng"
	"netprobe-ir/internal/report"
)

type Result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

func Run() []Result {
	var out []Result
	frame := httpFrame()
	p, err := decode.ParseEthernet(frame, time.Now(), "selftest0", model.DirectionOutbound)
	ok := err == nil && p.Protocol == "TCP" && p.DstPort == 80 && string(p.Payload) == "GET /health HTTP/1.1\r\nHost: test.local\r\n\r\n"
	out = append(out, Result{"decode_ipv4_tcp", ok, errString(err)})
	de := dpi.New(64 * 1024)
	id := "selftest-flow"
	di := de.Inspect(id, model.DirectionOutbound, p)
	ok = di.Protocol == "HTTP" && di.HTTP != nil && di.HTTP.Host == "test.local" && di.HTTP.Path == "/health"
	out = append(out, Result{"dpi_http", ok, fmt.Sprintf("protocol=%s host=%v", di.Protocol, func() string {
		if di.HTTP != nil {
			return di.HTTP.Host
		}
		return ""
	}())})
	st := flow.New(time.Minute)
	f, created := st.Observe(p, nil, "selftest", di, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, model.DirectionOutbound)
	ok = created && f.BytesTX == uint64(len(frame)) && f.PacketsTX == 1
	out = append(out, Result{"flow_accounting", ok, fmt.Sprintf("bytes=%d packets=%d", f.BytesTX, f.PacketsTX)})
	ae := anomaly.New(anomaly.Config{ExfiltrationBytes: 1})
	score, _, alerts := ae.Observe(f, true)
	ok = score > 0 && len(alerts) > 0
	out = append(out, Result{"anomaly_engine", ok, fmt.Sprintf("score=%d alerts=%d", score, len(alerts))})
	rd := report.Data{GeneratedAt: time.Now(), Status: model.Status{Packets: 1, Flows: 1}, Flows: []model.Flow{f}, Alerts: alerts, CaptureHealth: "healthy"}
	hb, he := report.HTML(rd)
	jb, je := report.JSON(rd)
	ok = he == nil && je == nil && len(hb) > 100 && len(jb) > 100
	out = append(out, Result{"report_render", ok, fmt.Sprintf("html=%d json=%d", len(hb), len(jb))})
	td, e := os.MkdirTemp("", "netprobe-selftest-")
	if e == nil {
		defer os.RemoveAll(td)
		rec := pcapng.New(filepath.Join(td, "pcap"), 1, 2, false)
		ctx, cancel := contextWithTimeout(500 * time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- rec.Run(ctx) }()
		time.Sleep(30 * time.Millisecond)
		rec.Record(capture.Frame{Time: time.Now(), Interface: "selftest0", Direction: model.DirectionOutbound, Data: frame})
		time.Sleep(30 * time.Millisecond)
		cancel()
		<-done
		files, _ := filepath.Glob(filepath.Join(td, "pcap", "*.pcapng"))
		if len(files) > 0 {
			e = pcapng.Validate(files[0])
		} else {
			e = fmt.Errorf("no pcapng generated")
		}
		out = append(out, Result{"pcapng_recorder", e == nil, errString(e)})
	} else {
		out = append(out, Result{"pcapng_recorder", false, e.Error()})
	}
	return out
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func httpFrame() []byte {
	payload := []byte("GET /health HTTP/1.1\r\nHost: test.local\r\n\r\n")
	ipLen := 20 + 20 + len(payload)
	b := make([]byte, 14+ipLen)
	copy(b[0:6], []byte{0, 1, 2, 3, 4, 5})
	copy(b[6:12], []byte{6, 7, 8, 9, 10, 11})
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	o := 14
	b[o] = 0x45
	binary.BigEndian.PutUint16(b[o+2:o+4], uint16(ipLen))
	b[o+8] = 64
	b[o+9] = 6
	copy(b[o+12:o+16], []byte{10, 0, 0, 1})
	copy(b[o+16:o+20], []byte{10, 0, 0, 2})
	t := o + 20
	binary.BigEndian.PutUint16(b[t:t+2], 54321)
	binary.BigEndian.PutUint16(b[t+2:t+4], 80)
	binary.BigEndian.PutUint32(b[t+4:t+8], 1000)
	b[t+12] = 0x50
	b[t+13] = 0x18
	copy(b[t+20:], payload)
	return b
}
