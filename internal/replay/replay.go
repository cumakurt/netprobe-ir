package replay

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/model"
)

type Stats struct {
	Frames uint64    `json:"frames"`
	Bytes  uint64    `json:"bytes"`
	First  time.Time `json:"first,omitempty"`
	Last   time.Time `json:"last,omitempty"`
}

func Stream(path string, fn func(capture.Frame) error) (Stats, error) {
	f, err := os.Open(path)
	if err != nil {
		return Stats{}, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		return Stats{}, err
	}
	if binary.LittleEndian.Uint32(magic) == 0x0A0D0D0A {
		return streamPCAPNG(br, fn)
	}
	mLE := binary.LittleEndian.Uint32(magic)
	mBE := binary.BigEndian.Uint32(magic)
	if mLE == 0xa1b2c3d4 || mLE == 0xa1b23c4d || mBE == 0xa1b2c3d4 || mBE == 0xa1b23c4d {
		return streamPCAP(br, fn)
	}
	return Stats{}, fmt.Errorf("unsupported capture format")
}

func note(st *Stats, fr capture.Frame) {
	st.Frames++
	st.Bytes += uint64(len(fr.Data))
	if st.First.IsZero() || fr.Time.Before(st.First) {
		st.First = fr.Time
	}
	if st.Last.IsZero() || fr.Time.After(st.Last) {
		st.Last = fr.Time
	}
}

func streamPCAPNG(r io.Reader, fn func(capture.Frame) error) (Stats, error) {
	var st Stats
	var endian binary.ByteOrder = binary.LittleEndian
	ifaces := map[uint32]string{}
	nextIface := uint32(0)
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return st, nil
			}
			return st, err
		}
		typ := endian.Uint32(hdr[:4])
		n := int(endian.Uint32(hdr[4:8]))
		if n < 12 || n > 64<<20 {
			return st, fmt.Errorf("invalid pcapng block length %d", n)
		}
		body := make([]byte, n-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return st, err
		}
		if endian.Uint32(body[len(body)-4:]) != uint32(n) {
			return st, fmt.Errorf("pcapng block trailer mismatch")
		}
		payload := body[:len(body)-4]
		switch typ {
		case 0x0A0D0D0A:
			if len(payload) < 16 {
				return st, fmt.Errorf("short section header")
			}
			bomLE := binary.LittleEndian.Uint32(payload[:4])
			bomBE := binary.BigEndian.Uint32(payload[:4])
			if bomLE == 0x1A2B3C4D {
				endian = binary.LittleEndian
			} else if bomBE == 0x1A2B3C4D {
				endian = binary.BigEndian
			} else {
				return st, fmt.Errorf("bad pcapng byte-order magic")
			}
			ifaces = map[uint32]string{}
			nextIface = 0
		case 1: // IDB
			name := fmt.Sprintf("replay%d", nextIface)
			if len(payload) >= 12 {
				pos := 8
				for pos+4 <= len(payload) {
					code := endian.Uint16(payload[pos : pos+2])
					l := int(endian.Uint16(payload[pos+2 : pos+4]))
					pos += 4
					if code == 0 {
						break
					}
					if pos+l > len(payload) {
						break
					}
					if code == 2 {
						name = strings.TrimSpace(string(payload[pos : pos+l]))
					}
					pos += (l + 3) &^ 3
				}
			}
			ifaces[nextIface] = name
			nextIface++
		case 6: // EPB
			if len(payload) < 20 {
				continue
			}
			id := endian.Uint32(payload[0:4])
			hi := uint64(endian.Uint32(payload[4:8]))
			lo := uint64(endian.Uint32(payload[8:12]))
			caplen := int(endian.Uint32(payload[12:16]))
			if caplen < 0 || 20+caplen > len(payload) {
				continue
			}
			usec := (hi << 32) | lo
			fr := capture.Frame{Time: time.Unix(0, int64(usec)*1000), Interface: ifaces[id], Direction: model.DirectionUnknown, Data: append([]byte(nil), payload[20:20+caplen]...)}
			if fr.Interface == "" {
				fr.Interface = fmt.Sprintf("replay%d", id)
			}
			if err := fn(fr); err != nil {
				return st, err
			}
			note(&st, fr)
		}
	}
}

func streamPCAP(r io.Reader, fn func(capture.Frame) error) (Stats, error) {
	var st Stats
	var gh [24]byte
	if _, err := io.ReadFull(r, gh[:]); err != nil {
		return st, err
	}
	mle := binary.LittleEndian.Uint32(gh[:4])
	mbe := binary.BigEndian.Uint32(gh[:4])
	var endian binary.ByteOrder = binary.LittleEndian
	nano := false
	switch {
	case mle == 0xa1b2c3d4:
		endian = binary.LittleEndian
	case mbe == 0xa1b2c3d4:
		endian = binary.BigEndian
	case mle == 0xa1b23c4d:
		endian = binary.LittleEndian
		nano = true
	case mbe == 0xa1b23c4d:
		endian = binary.BigEndian
		nano = true
	default:
		return st, fmt.Errorf("bad pcap magic")
	}
	if endian.Uint32(gh[20:24]) != 1 {
		return st, fmt.Errorf("only Ethernet PCAP linktype is supported")
	}
	for {
		var ph [16]byte
		if _, err := io.ReadFull(r, ph[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return st, nil
			}
			return st, err
		}
		sec := endian.Uint32(ph[0:4])
		frac := endian.Uint32(ph[4:8])
		incl := int(endian.Uint32(ph[8:12]))
		if incl < 0 || incl > 16<<20 {
			return st, fmt.Errorf("invalid pcap packet length")
		}
		b := make([]byte, incl)
		if _, err := io.ReadFull(r, b); err != nil {
			return st, err
		}
		ns := int64(frac) * 1000
		if nano {
			ns = int64(frac)
		}
		fr := capture.Frame{Time: time.Unix(int64(sec), ns), Interface: "replay0", Direction: model.DirectionUnknown, Data: b}
		if err := fn(fr); err != nil {
			return st, err
		}
		note(&st, fr)
	}
}
