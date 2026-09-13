package dpi

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"strconv"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

// Observations describe new messages, never the cached classification of an ACK.
func observeMessages(st *flowState, p *decode.Packet, max int) []model.DPIInfo {
	var out []model.DPIInfo
	dns := p.SrcPort == 53 || p.DstPort == 53
	addDNS := func(b []byte) {
		if d, ok := parseDNS(b); ok {
			out = append(out, model.DPIInfo{Protocol: "DNS", DNS: &d, Confidence: 100})
		}
	}
	if p.Protocol == "UDP" && dns {
		addDNS(p.Payload)
		return out
	}
	if p.Protocol != "TCP" || len(p.Payload) == 0 {
		return out
	}
	source := p.SrcIP + ":" + strconv.Itoa(int(p.SrcPort))
	if st.observationSource == "" {
		st.observationSource = source
	}
	s := &st.observationTX
	if source != st.observationSource {
		s = &st.observationRX
	}
	appendSegment(s, p.TCPSeq, p.Payload, max)
	for len(s.buf) > 0 {
		if dns {
			if len(s.buf) < 2 {
				break
			}
			size := 2 + int(binary.BigEndian.Uint16(s.buf[:2]))
			if len(s.buf) < size {
				break
			}
			addDNS(s.buf[2:size])
			s.buf = s.buf[size:]
			continue
		}
		// Consume complete HTTP/1 messages, including bodies, so keep-alive
		// requests and retransmissions do not repeat the first URL in a stream.
		h, ok := parseHTTP(s.buf)
		if !ok || h.Method == "PRI" {
			break
		}
		raw := bytes.NewReader(s.buf)
		reader := bufio.NewReader(raw)
		var body io.ReadCloser
		closeDelimited := false
		if h.Method != "" {
			req, err := http.ReadRequest(reader)
			if err != nil {
				break
			}
			body = req.Body
		} else {
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				break
			}
			// Close-delimited bodies cannot be framed until connection closure.
			closeDelimited = resp.ContentLength < 0 && len(resp.TransferEncoding) == 0
			body = resp.Body
		}
		if !s.observedHeader {
			out = append(out, model.DPIInfo{Protocol: "HTTP", HTTP: &h, Confidence: 100})
			s.observedHeader = true
		}
		if closeDelimited {
			body.Close()
			break
		}
		_, err := io.Copy(io.Discard, body)
		body.Close()
		if err != nil {
			break
		}
		consumed := len(s.buf) - raw.Len() - reader.Buffered()
		if consumed <= 0 {
			break
		}
		s.observedHeader = false
		s.buf = s.buf[consumed:]
	}
	return out
}
