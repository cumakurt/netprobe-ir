//go:build linux

package capture

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"netprobe-ir/internal/model"
)

const (
	solPacket     = 263
	packetRXRing  = 5
	packetVersion = 10
	tpacketV3     = 2
	tpStatusUser  = 1
)

type tpacketReq3 struct{ BlockSize, BlockNr, FrameSize, FrameNr, RetireBlkTov, SizeofPriv, FeatureReqWord uint32 }

type PacketMMap struct {
	Interface       string
	SnapLen         int
	ReceiveBuffer   int
	DirectionFilter model.Direction
	Stats           Stats
}

func (p *PacketMMap) Backend() string      { return "tpacket_v3" }
func (p *PacketMMap) StatsView() StatsView { return p.Stats.View() }
func rawSetsockopt(fd, level, opt int, ptr unsafe.Pointer, n uintptr) error {
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt), uintptr(ptr), n, 0)
	if e != 0 {
		return e
	}
	return nil
}
func (p *PacketMMap) Run(ctx context.Context, out chan<- Frame) error {
	ni, e := net.InterfaceByName(p.Interface)
	if e != nil {
		return e
	}
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if e != nil {
		return fmt.Errorf("TPACKET socket: %w", e)
	}
	defer syscall.Close(fd)
	if e = syscall.SetsockoptInt(fd, solPacket, packetVersion, tpacketV3); e != nil {
		return fmt.Errorf("PACKET_VERSION TPACKET_V3: %w", e)
	}
	blockSize := uint32(1 << 20)
	frameSize := uint32(1 << 16)
	buf := p.ReceiveBuffer
	if buf < 4<<20 {
		buf = 4 << 20
	}
	if buf > 64<<20 {
		buf = 64 << 20
	}
	blockNr := uint32(buf / int(blockSize))
	if blockNr < 4 {
		blockNr = 4
	}
	req := tpacketReq3{BlockSize: blockSize, BlockNr: blockNr, FrameSize: frameSize, FrameNr: blockNr * (blockSize / frameSize), RetireBlkTov: 64}
	if e = rawSetsockopt(fd, solPacket, packetRXRing, unsafe.Pointer(&req), unsafe.Sizeof(req)); e != nil {
		return fmt.Errorf("PACKET_RX_RING: %w", e)
	}
	ringSize := int(req.BlockSize * req.BlockNr)
	ring, e := syscall.Mmap(fd, 0, ringSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if e != nil {
		return fmt.Errorf("packet ring mmap: %w", e)
	}
	defer syscall.Munmap(ring)
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(0x0003), Ifindex: ni.Index}); e != nil {
		return fmt.Errorf("bind %s: %w", p.Interface, e)
	}
	snap := p.SnapLen
	if snap <= 0 || snap > 65535 {
		snap = 65535
	}
	block := uint32(0)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		base := unsafe.Add(unsafe.Pointer(&ring[0]), uintptr(block*req.BlockSize))
		status := (*uint32)(unsafe.Add(base, 8))
		if atomic.LoadUint32(status)&tpStatusUser == 0 {
			waitFD(fd, 20*time.Millisecond)
			continue
		}
		num := *(*uint32)(unsafe.Add(base, 12))
		off := *(*uint32)(unsafe.Add(base, 16))
		for i := uint32(0); i < num; i++ {
			h := unsafe.Add(base, uintptr(off))
			next := *(*uint32)(h)
			sec := *(*uint32)(unsafe.Add(h, 4))
			nsec := *(*uint32)(unsafe.Add(h, 8))
			caplen := int(*(*uint32)(unsafe.Add(h, 12)))
			mac := *(*uint16)(unsafe.Add(h, 24))
			if caplen > snap {
				caplen = snap
			}
			if caplen > 0 && uintptr(off)+uintptr(mac)+uintptr(caplen) <= uintptr(req.BlockSize) {
				pkttype := *(*uint8)(unsafe.Add(h, 58))
				dir := model.DirectionInbound
				if pkttype == 4 {
					dir = model.DirectionOutbound
				}
				if p.DirectionFilter == "" || p.DirectionFilter == model.DirectionUnknown || p.DirectionFilter == dir {
					data := make([]byte, caplen)
					copy(data, unsafe.Slice((*byte)(unsafe.Add(h, uintptr(mac))), caplen))
					p.Stats.Packets.Add(1)
					p.Stats.Bytes.Add(uint64(caplen))
					select {
					case out <- Frame{Time: time.Unix(int64(sec), int64(nsec)), Interface: p.Interface, Direction: dir, Data: data}:
					default:
						p.Stats.Dropped.Add(1)
					}
				}
			}
			if next == 0 {
				break
			}
			off += next
		}
		atomic.StoreUint32(status, 0)
		block = (block + 1) % req.BlockNr
		runtime.Gosched()
	}
}
func waitFD(fd int, d time.Duration) {
	var rf syscall.FdSet
	if fd < 0 || fd >= len(rf.Bits)*64 {
		time.Sleep(d)
		return
	}
	rf.Bits[fd/64] |= 1 << uint(fd%64)
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	_, _ = syscall.Select(fd+1, &rf, nil, nil, &tv)
}

// ProbeAFXDP reports kernel socket-family availability only. NetProbe does not
// redirect passive host traffic into AF_XDP because XDP_REDIRECT consumes the
// packet unless userspace implements an inline forwarding path.
func ProbeAFXDP() (bool, string) {
	const afXDP = 44
	fd, e := syscall.Socket(afXDP, syscall.SOCK_RAW, 0)
	if e != nil {
		return false, e.Error()
	}
	syscall.Close(fd)
	return true, "AF_XDP socket family available; passive redirect intentionally disabled"
}
