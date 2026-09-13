package fileextract

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

type Config struct {
	Enabled               bool
	MaxFileBytes          int
	MaxArtifacts          int
	StorePayload          bool
	YaraBinary, YaraRules string
}

type streamState struct {
	buf    []byte
	parsed int
}
type ftpSession struct {
	passiveIP   string
	passivePort uint16
	filename    string
	mode        string
	updated     time.Time
}
type smbState struct {
	pending map[uint64]string
	files   map[string]string
	data    map[string][]byte
}

type scanJob struct{ ID, Path string }
type Engine struct {
	mu        sync.Mutex
	cfg       Config
	dir       string
	scanner   Scanner
	seq       atomic.Uint64
	streams   map[string]*streamState
	ftp       map[string]*ftpSession
	ftpData   map[string]*ftpSession
	smb       map[string]*smbState
	artifacts []model.FileArtifact
	scanCh    chan scanJob
	updates   chan model.FileArtifact
}

func New(dir string, cfg Config, scanner Scanner) *Engine {
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = 32 << 20
	}
	if cfg.MaxArtifacts <= 0 {
		cfg.MaxArtifacts = 2000
	}
	if scanner == nil && cfg.YaraRules != "" {
		scanner = &YaraXScanner{Binary: cfg.YaraBinary, Rules: cfg.YaraRules}
	}
	return &Engine{cfg: cfg, dir: dir, scanner: scanner, streams: map[string]*streamState{}, ftp: map[string]*ftpSession{}, ftpData: map[string]*ftpSession{}, smb: map[string]*smbState{}, artifacts: make([]model.FileArtifact, 0, 128), scanCh: make(chan scanJob, 256), updates: make(chan model.FileArtifact, 256)}
}
func (e *Engine) AvailableYara() bool { return e.scanner != nil && e.scanner.Available() }
func (e *Engine) List(limit int) []model.FileArtifact {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit > len(e.artifacts) {
		limit = len(e.artifacts)
	}
	out := make([]model.FileArtifact, limit)
	copy(out, e.artifacts[len(e.artifacts)-limit:])
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
func (e *Engine) Updates() <-chan model.FileArtifact { return e.updates }
func (e *Engine) Start(ctx context.Context) {
	if e == nil || e.scanner == nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case j := <-e.scanCh:
				matches, err := e.scanner.Scan(j.Path)
				e.mu.Lock()
				var updated *model.FileArtifact
				for i := range e.artifacts {
					if e.artifacts[i].ID == j.ID {
						if err == nil {
							e.artifacts[i].Yara = matches
						} else {
							if e.artifacts[i].Meta == nil {
								e.artifacts[i].Meta = map[string]any{}
							}
							e.artifacts[i].Meta["yara_error"] = err.Error()
						}
						cp := e.artifacts[i]
						updated = &cp
						break
					}
				}
				e.mu.Unlock()
				if updated != nil {
					select {
					case e.updates <- *updated:
					default:
					}
				}
			}
		}
	}()
}

func (e *Engine) Get(id string) (model.FileArtifact, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.artifacts) - 1; i >= 0; i-- {
		if e.artifacts[i].ID == id {
			return e.artifacts[i], true
		}
	}
	return model.FileArtifact{}, false
}

func flowDirKey(flowID string, d model.Direction) string { return flowID + "|" + string(d) }
func endpointKey(ip string, p uint16) string             { return ip + ":" + strconv.Itoa(int(p)) }
func ftpControlKey(p *decode.Packet) string {
	a := endpointKey(p.SrcIP, p.SrcPort)
	b := endpointKey(p.DstIP, p.DstPort)
	if a > b {
		return b + "|" + a
	}
	return a + "|" + b
}

// Observe consumes decoded packet metadata after DPI. It performs bounded, in-order
// application reconstruction. It never blocks packet capture on external scanning;
// callers should invoke it on the pipeline goroutine only with conservative limits.
func (e *Engine) Observe(p *decode.Packet, f model.Flow, di model.DPIInfo) []model.FileArtifact {
	if e == nil || !e.cfg.Enabled || p == nil || len(p.Payload) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []model.FileArtifact
	proto := strings.ToUpper(di.Protocol + " " + di.Application)
	if strings.Contains(proto, "HTTP") && !strings.Contains(proto, "HTTP/2") {
		out = append(out, e.observeHTTP(p, f)...)
	}
	if p.SrcPort == 25 || p.DstPort == 25 || p.SrcPort == 587 || p.DstPort == 587 {
		out = append(out, e.observeSMTP(p, f)...)
	}
	if p.SrcPort == 21 || p.DstPort == 21 {
		e.observeFTPControl(p)
	} else if sess := e.ftpData[endpointKey(p.DstIP, p.DstPort)]; sess != nil || e.ftpData[endpointKey(p.SrcIP, p.SrcPort)] != nil {
		if sess == nil {
			sess = e.ftpData[endpointKey(p.SrcIP, p.SrcPort)]
		}
		out = append(out, e.observeFTPData(p, f, sess)...)
	}
	if p.SrcPort == 445 || p.DstPort == 445 || strings.Contains(proto, "SMB") {
		out = append(out, e.observeSMB(p, f)...)
	}
	for _, a := range out {
		e.appendArtifact(a)
	}
	return out
}
func (e *Engine) appendArtifact(a model.FileArtifact) {
	e.artifacts = append(e.artifacts, a)
	if len(e.artifacts) > e.cfg.MaxArtifacts {
		e.artifacts = append([]model.FileArtifact(nil), e.artifacts[len(e.artifacts)-e.cfg.MaxArtifacts:]...)
	}
	if a.StoredPath != "" && e.scanner != nil && e.scanner.Available() {
		select {
		case e.scanCh <- scanJob{ID: a.ID, Path: a.StoredPath}:
		default:
			if a.Meta == nil {
				a.Meta = map[string]any{}
			}
			a.Meta["yara_dropped"] = true
		}
	}
}

func (e *Engine) artifact(f model.Flow, p *decode.Packet, protocol, name string, data []byte, meta map[string]any) model.FileArtifact {
	if len(data) > e.cfg.MaxFileBytes {
		data = data[:e.cfg.MaxFileBytes]
		if meta == nil {
			meta = map[string]any{}
		}
		meta["truncated"] = true
	}
	h256 := sha256.Sum256(data)
	h1 := sha1.Sum(data)
	hm := md5.Sum(data)
	id := fmt.Sprintf("file-%d-%s", e.seq.Add(1), hex.EncodeToString(h256[:4]))
	if name == "" {
		name = id + ".bin"
	}
	name = safeName(name)
	a := model.FileArtifact{ID: id, Time: p.Time, FlowID: f.ID, Protocol: protocol, Direction: f.Direction, Name: name, MIME: http.DetectContentType(data), Size: int64(len(data)), SHA256: hex.EncodeToString(h256[:]), SHA1: hex.EncodeToString(h1[:]), MD5: hex.EncodeToString(hm[:]), Entropy: entropy(data), Source: model.Endpoint{IP: p.SrcIP, Port: p.SrcPort}, Destination: model.Endpoint{IP: p.DstIP, Port: p.DstPort}, Meta: meta}
	if f.Process != nil {
		cp := *f.Process
		a.Process = &cp
	}
	if e.cfg.StorePayload {
		_ = os.MkdirAll(e.dir, 0750)
		path := filepath.Join(e.dir, id+"-"+name)
		if os.WriteFile(path, data, 0640) == nil {
			a.StoredPath = path
		}
	}
	return a
}
func safeName(s string) string {
	s = filepath.Base(strings.TrimSpace(s))
	if s == "." || s == "/" || s == "" {
		return "artifact.bin"
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	x := b.String()
	if len(x) > 160 {
		x = x[:160]
	}
	return x
}
func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var c [256]int
	for _, x := range b {
		c[x]++
	}
	var h float64
	for _, n := range c {
		if n == 0 {
			continue
		}
		p := float64(n) / float64(len(b))
		h -= p * math.Log2(p)
	}
	return math.Round(h*1000) / 1000
}

func (e *Engine) appendStream(k string, payload []byte) *streamState {
	st := e.streams[k]
	if st == nil {
		st = &streamState{}
		e.streams[k] = st
	}
	remain := e.cfg.MaxFileBytes*2 - len(st.buf)
	if remain > 0 {
		if len(payload) > remain {
			payload = payload[:remain]
		}
		st.buf = append(st.buf, payload...)
	}
	return st
}
func parseHeaders(h []byte) map[string]string {
	m := map[string]string{}
	lines := strings.Split(string(h), "\r\n")
	for _, l := range lines[1:] {
		if i := strings.IndexByte(l, ':'); i > 0 {
			m[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(l[i+1:])
		}
	}
	return m
}
func contentName(headers map[string]string, start string) string {
	if cd := headers["content-disposition"]; cd != "" {
		_, p, _ := mime.ParseMediaType(cd)
		if p["filename"] != "" {
			return p["filename"]
		}
	}
	fld := strings.Fields(start)
	if len(fld) >= 2 && !strings.HasPrefix(fld[0], "HTTP/") {
		if x := filepath.Base(strings.Split(fld[1], "?")[0]); x != "" && x != "/" && x != "." {
			return x
		}
	}
	return "http-body.bin"
}
func decodeChunked(b []byte) ([]byte, int, bool) {
	var out []byte
	pos := 0
	for {
		j := bytes.Index(b[pos:], []byte("\r\n"))
		if j < 0 {
			return nil, 0, false
		}
		line := string(b[pos : pos+j])
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		n, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil || n < 0 {
			return nil, 0, false
		}
		pos += j + 2
		if n == 0 {
			if len(b) < pos+2 {
				return nil, 0, false
			}
			return out, pos + 2, true
		}
		if int64(len(b)-pos) < n+2 {
			return nil, 0, false
		}
		out = append(out, b[pos:pos+int(n)]...)
		pos += int(n) + 2
	}
}
func (e *Engine) observeHTTP(p *decode.Packet, f model.Flow) []model.FileArtifact {
	st := e.appendStream(flowDirKey(f.ID, f.Direction), p.Payload)
	var out []model.FileArtifact
	for {
		if st.parsed >= len(st.buf) {
			break
		}
		b := st.buf[st.parsed:]
		hi := bytes.Index(b, []byte("\r\n\r\n"))
		if hi < 0 {
			break
		}
		head := b[:hi]
		lines := strings.Split(string(head), "\r\n")
		if len(lines) == 0 {
			break
		}
		start := lines[0]
		if !(strings.HasPrefix(start, "HTTP/") || strings.Contains(start, " HTTP/")) {
			st.parsed++
			continue
		}
		headers := parseHeaders(head)
		bodyPos := hi + 4
		var body []byte
		consumed := 0
		if strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked") {
			d, n, ok := decodeChunked(b[bodyPos:])
			if !ok {
				break
			}
			body = d
			consumed = bodyPos + n
		} else if cl, err := strconv.Atoi(headers["content-length"]); err == nil && cl > 0 {
			if cl > e.cfg.MaxFileBytes*2 {
				cl = e.cfg.MaxFileBytes * 2
			}
			if len(b) < bodyPos+cl {
				break
			}
			body = b[bodyPos : bodyPos+cl]
			consumed = bodyPos + cl
		} else {
			st.parsed += bodyPos
			continue
		}
		if len(body) > 0 {
			out = append(out, e.artifact(f, p, "HTTP", contentName(headers, start), body, map[string]any{"start_line": start, "content_type": headers["content-type"]}))
		}
		st.parsed += consumed
	}
	return out
}

func (e *Engine) observeSMTP(p *decode.Packet, f model.Flow) []model.FileArtifact {
	st := e.appendStream(flowDirKey(f.ID, f.Direction), p.Payload)
	b := st.buf
	idx := bytes.Index(bytes.ToUpper(b), []byte("DATA\r\n"))
	if idx < 0 {
		return nil
	}
	end := bytes.Index(b[idx+6:], []byte("\r\n.\r\n"))
	if end < 0 {
		return nil
	}
	msgBytes := b[idx+6 : idx+6+end]
	st.parsed = idx + 6 + end + 5
	msg, err := mail.ReadMessage(bytes.NewReader(msgBytes))
	if err != nil {
		return nil
	}
	ct := msg.Header.Get("Content-Type")
	mt, params, _ := mime.ParseMediaType(ct)
	var out []model.FileArtifact
	if strings.HasPrefix(mt, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			part, er := mr.NextPart()
			if er == io.EOF {
				break
			}
			if er != nil {
				break
			}
			d, _ := io.ReadAll(io.LimitReader(part, int64(e.cfg.MaxFileBytes)+1))
			if strings.EqualFold(part.Header.Get("Content-Transfer-Encoding"), "base64") {
				if dec, er := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(d))); er == nil {
					d = dec
				}
			}
			fn := part.FileName()
			if fn == "" {
				continue
			}
			out = append(out, e.artifact(f, p, "SMTP", fn, d, map[string]any{"subject": msg.Header.Get("Subject"), "from": msg.Header.Get("From"), "to": msg.Header.Get("To")}))
		}
	}
	return out
}

func (e *Engine) observeFTPControl(p *decode.Packet) {
	k := ftpControlKey(p)
	s := e.ftp[k]
	if s == nil {
		s = &ftpSession{}
		e.ftp[k] = s
	}
	txt := strings.TrimSpace(string(p.Payload))
	up := strings.ToUpper(txt)
	if strings.HasPrefix(up, "227 ") {
		if a := strings.LastIndex(txt, "("); a >= 0 {
			if b := strings.Index(txt[a:], ")"); b > 0 {
				parts := strings.Split(txt[a+1:a+b], ",")
				if len(parts) == 6 {
					ip := strings.Join(parts[:4], ".")
					p1, _ := strconv.Atoi(parts[4])
					p2, _ := strconv.Atoi(parts[5])
					s.passiveIP = ip
					s.passivePort = uint16(p1*256 + p2)
				}
			}
		}
	}
	if strings.HasPrefix(up, "229 ") {
		if a := strings.LastIndex(txt, "(|||"); a >= 0 {
			if b := strings.Index(txt[a+4:], "|"); b >= 0 {
				n, _ := strconv.Atoi(txt[a+4 : a+4+b])
				s.passiveIP = p.SrcIP
				s.passivePort = uint16(n)
			}
		}
	}
	if strings.HasPrefix(up, "PORT ") {
		v := strings.Split(strings.TrimSpace(txt[5:]), ",")
		if len(v) == 6 {
			p1, _ := strconv.Atoi(v[4])
			p2, _ := strconv.Atoi(v[5])
			s.passiveIP = strings.Join(v[:4], ".")
			s.passivePort = uint16(p1*256 + p2)
		}
	}
	if strings.HasPrefix(up, "RETR ") || strings.HasPrefix(up, "STOR ") {
		s.mode = strings.Fields(up)[0]
		s.filename = strings.TrimSpace(txt[5:])
		s.updated = time.Now()
		if s.passivePort > 0 {
			e.ftpData[endpointKey(s.passiveIP, s.passivePort)] = s
		}
	}
}
func (e *Engine) observeFTPData(p *decode.Packet, f model.Flow, s *ftpSession) []model.FileArtifact {
	k := flowDirKey(f.ID, f.Direction) + "|ftp"
	st := e.appendStream(k, p.Payload)
	if p.TCPFlags&0x01 == 0 && p.TCPFlags&0x04 == 0 {
		return nil
	}
	delete(e.streams, k)
	if len(st.buf) == 0 {
		return nil
	}
	a := e.artifact(f, p, "FTP", s.filename, st.buf, map[string]any{"ftp_command": s.mode})
	return []model.FileArtifact{a}
}

func smbMsg(payload []byte) []byte {
	if len(payload) >= 8 && payload[0] == 0 && bytes.Equal(payload[4:8], []byte{0xfe, 'S', 'M', 'B'}) {
		return payload[4:]
	}
	if len(payload) >= 4 && bytes.Equal(payload[:4], []byte{0xfe, 'S', 'M', 'B'}) {
		return payload
	}
	return nil
}
func utf16Name(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
func fileIDKey(b []byte) string { return hex.EncodeToString(b) }
func (e *Engine) observeSMB(p *decode.Packet, f model.Flow) []model.FileArtifact {
	m := smbMsg(p.Payload)
	if len(m) < 64 {
		return nil
	}
	cmd := binary.LittleEndian.Uint16(m[12:14])
	flags := binary.LittleEndian.Uint32(m[16:20])
	mid := binary.LittleEndian.Uint64(m[24:32])
	response := flags&1 != 0
	st := e.smb[f.ID]
	if st == nil {
		st = &smbState{pending: map[uint64]string{}, files: map[string]string{}, data: map[string][]byte{}}
		e.smb[f.ID] = st
	}
	body := m[64:]
	switch cmd {
	case 5: // CREATE
		if !response && len(body) >= 48 {
			nameOff := int(binary.LittleEndian.Uint16(body[44:46]))
			nameLen := int(binary.LittleEndian.Uint16(body[46:48]))
			if nameOff >= 64 && nameLen > 0 && nameOff+nameLen <= len(m) {
				st.pending[mid] = utf16Name(m[nameOff : nameOff+nameLen])
			}
		} else if response && len(body) >= 80 {
			name := st.pending[mid]
			if name != "" {
				st.files[fileIDKey(body[64:80])] = name
				delete(st.pending, mid)
			}
		}
	case 9: // WRITE
		if !response && len(body) >= 32 {
			off := int(binary.LittleEndian.Uint16(body[2:4]))
			ln := int(binary.LittleEndian.Uint32(body[4:8]))
			fid := fileIDKey(body[16:32])
			if off >= 64 && ln > 0 && off+ln <= len(m) {
				buf := st.data[fid]
				remain := e.cfg.MaxFileBytes - len(buf)
				if remain > 0 {
					d := m[off : off+ln]
					if len(d) > remain {
						d = d[:remain]
					}
					st.data[fid] = append(buf, d...)
				}
			}
		}
	case 6: // CLOSE
		if !response && len(body) >= 24 {
			fid := fileIDKey(body[8:24])
			d := st.data[fid]
			name := st.files[fid]
			delete(st.data, fid)
			delete(st.files, fid)
			if len(d) > 0 {
				return []model.FileArtifact{e.artifact(f, p, "SMB2", name, d, map[string]any{"smb2_file_id": fid})}
			}
		}
	}
	return nil
}
