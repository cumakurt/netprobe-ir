package pcapng

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/capture"
)

type Recorder struct {
	dir            string
	incidents      string
	segmentBytes   int64
	maxBytes       int64
	incidentCopies bool
	ch             chan capture.Frame
	drops          atomic.Uint64
	mu             sync.Mutex
	f              *os.File
	bw             *bufio.Writer
	current        string
	written        int64
	ifaces         map[string]uint32
	recent         []string
}

func New(dir string, segmentMB, maxDiskMB int64, incident bool) *Recorder {
	if segmentMB <= 0 {
		segmentMB = 64
	}
	if maxDiskMB <= 0 {
		maxDiskMB = 1024
	}
	return &Recorder{dir: dir, incidents: filepath.Join(filepath.Dir(dir), "incidents"), segmentBytes: segmentMB << 20, maxBytes: maxDiskMB << 20, incidentCopies: incident, ch: make(chan capture.Frame, 8192), ifaces: map[string]uint32{}}
}
func (r *Recorder) Drops() uint64 { return r.drops.Load() }
func (r *Recorder) Record(f capture.Frame) bool {
	select {
	case r.ch <- f:
		return true
	default:
		r.drops.Add(1)
		return false
	}
}
func (r *Recorder) Run(ctx context.Context) error {
	if err := os.MkdirAll(r.dir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(r.incidents, 0750); err != nil {
		return err
	}
	if err := r.rotate(); err != nil {
		return err
	}
	defer r.closeCurrent()
	for {
		select {
		case <-ctx.Done():
			return nil
		case f := <-r.ch:
			if err := r.writeFrame(f); err != nil {
				return err
			}
		}
	}
}
func (r *Recorder) writeFrame(fr capture.Frame) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.written >= r.segmentBytes {
		if err := r.rotateLocked(); err != nil {
			return err
		}
	}
	id, ok := r.ifaces[fr.Interface]
	if !ok {
		id = uint32(len(r.ifaces))
		r.ifaces[fr.Interface] = id
		if err := writeIDB(r.bw, fr.Interface); err != nil {
			return err
		}
		r.written += int64(idbSize(fr.Interface))
	}
	n, err := writeEPB(r.bw, id, fr.Time, fr.Data)
	r.written += int64(n)
	return err
}
func (r *Recorder) rotate() error { r.mu.Lock(); defer r.mu.Unlock(); return r.rotateLocked() }
func (r *Recorder) rotateLocked() error {
	if r.bw != nil {
		_ = r.bw.Flush()
	}
	if r.f != nil {
		_ = r.f.Sync()
		_ = r.f.Close()
		if r.current != "" {
			r.recent = append(r.recent, r.current)
			if len(r.recent) > 4 {
				r.recent = r.recent[len(r.recent)-4:]
			}
		}
	}
	name := filepath.Join(r.dir, "netprobe-"+time.Now().Format("20060102-150405.000000000")+".pcapng")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	r.f = f
	r.bw = bufio.NewWriterSize(f, 1<<20)
	r.current = name
	r.written = 0
	r.ifaces = map[string]uint32{}
	if err := writeSHB(r.bw); err != nil {
		return err
	}
	r.written = 28
	go r.prune()
	return nil
}
func (r *Recorder) closeCurrent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bw != nil {
		_ = r.bw.Flush()
	}
	if r.f != nil {
		_ = r.f.Sync()
		_ = r.f.Close()
	}
}
func (r *Recorder) Protect(reason string) []string {
	if !r.incidentCopies {
		return nil
	}
	// Close the alert-time segment before copying it. This guarantees that
	// every protected PCAPNG is a stable block-complete forensic artifact.
	r.mu.Lock()
	_ = r.rotateLocked()
	files := append([]string(nil), r.recent...)
	r.mu.Unlock()
	if len(files) > 2 {
		files = files[len(files)-2:]
	}
	tag := sanitize(reason)
	var out []string
	for _, src := range files {
		dst := filepath.Join(r.incidents, time.Now().Format("20060102-150405")+"-"+tag+"-"+filepath.Base(src))
		if copyFile(src, dst) == nil {
			out = append(out, dst)
		}
	}
	return out
}
func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
			b.WriteByte('-')
		}
	}
	x := strings.Trim(b.String(), "-")
	if x == "" {
		x = "incident"
	}
	if len(x) > 40 {
		x = x[:40]
	}
	return x
}
func copyFile(src, dst string) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	ce := out.Close()
	if e != nil {
		return e
	}
	return ce
}
func (r *Recorder) prune() {
	ents, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	type fi struct {
		p string
		s int64
		t time.Time
	}
	var fs []fi
	var total int64
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pcapng") {
			continue
		}
		i, er := e.Info()
		if er != nil {
			continue
		}
		fs = append(fs, fi{filepath.Join(r.dir, e.Name()), i.Size(), i.ModTime()})
		total += i.Size()
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].t.Before(fs[j].t) })
	for _, f := range fs {
		if total <= r.maxBytes {
			break
		}
		r.mu.Lock()
		cur := r.current
		r.mu.Unlock()
		if f.p == cur {
			continue
		}
		if os.Remove(f.p) == nil {
			total -= f.s
		}
	}
}

func writeSHB(w io.Writer) error {
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b[0:4], 0x0A0D0D0A)
	binary.LittleEndian.PutUint32(b[4:8], 28)
	binary.LittleEndian.PutUint32(b[8:12], 0x1A2B3C4D)
	binary.LittleEndian.PutUint16(b[12:14], 1)
	binary.LittleEndian.PutUint16(b[14:16], 0)
	binary.LittleEndian.PutUint64(b[16:24], ^uint64(0))
	binary.LittleEndian.PutUint32(b[24:28], 28)
	_, e := w.Write(b)
	return e
}
func idbSize(name string) int { pad := (4 - len(name)%4) % 4; return 28 + len(name) + pad }
func writeIDB(w io.Writer, name string) error {
	pad := (4 - len(name)%4) % 4
	total := idbSize(name)
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:4], 1)
	binary.LittleEndian.PutUint32(b[4:8], uint32(total))
	binary.LittleEndian.PutUint16(b[8:10], 1) // LINKTYPE_ETHERNET
	binary.LittleEndian.PutUint32(b[12:16], 65535)
	pos := 16
	binary.LittleEndian.PutUint16(b[pos:pos+2], 2) // if_name
	binary.LittleEndian.PutUint16(b[pos+2:pos+4], uint16(len(name)))
	copy(b[pos+4:pos+4+len(name)], []byte(name))
	pos += 4 + len(name) + pad
	// End-of-options is already zeroed at pos:pos+4.
	binary.LittleEndian.PutUint32(b[total-4:], uint32(total))
	_, e := w.Write(b)
	return e
}
func writeEPB(w io.Writer, id uint32, ts time.Time, data []byte) (int, error) {
	pad := (4 - len(data)%4) % 4
	total := 32 + len(data) + pad
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:4], 6)
	binary.LittleEndian.PutUint32(b[4:8], uint32(total))
	binary.LittleEndian.PutUint32(b[8:12], id)
	u := uint64(ts.UnixNano() / 1000)
	binary.LittleEndian.PutUint32(b[12:16], uint32(u>>32))
	binary.LittleEndian.PutUint32(b[16:20], uint32(u))
	binary.LittleEndian.PutUint32(b[20:24], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[24:28], uint32(len(data)))
	copy(b[28:28+len(data)], data)
	binary.LittleEndian.PutUint32(b[total-4:], uint32(total))
	_, e := w.Write(b)
	return total, e
}

func Validate(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) < 28 {
		return fmt.Errorf("pcapng too short")
	}
	if binary.LittleEndian.Uint32(b[:4]) != 0x0A0D0D0A {
		return fmt.Errorf("bad section header")
	}
	pos := 0
	for pos+12 <= len(b) {
		n := int(binary.LittleEndian.Uint32(b[pos+4 : pos+8]))
		if n < 12 || pos+n > len(b) {
			return fmt.Errorf("invalid block length at %d", pos)
		}
		if binary.LittleEndian.Uint32(b[pos+n-4:pos+n]) != uint32(n) {
			return fmt.Errorf("block trailer mismatch at %d", pos)
		}
		pos += n
	}
	if pos != len(b) {
		return fmt.Errorf("trailing bytes")
	}
	return nil
}
