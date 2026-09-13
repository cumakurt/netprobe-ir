//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"netprobe-ir/internal/model"
)

type AFPacket struct {
	Interface       string
	SnapLen         int
	ReceiveBuffer   int
	DirectionFilter model.Direction
	Stats           Stats
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func (a *AFPacket) Run(ctx context.Context, out chan<- Frame) error {
	ni, err := net.InterfaceByName(a.Interface)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)
	if a.ReceiveBuffer > 0 {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, a.ReceiveBuffer)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(0x0003), Ifindex: ni.Index}); err != nil {
		return fmt.Errorf("bind %s: %w", a.Interface, err)
	}
	// A receive timeout allows cancellation to be observed without forcing nonblocking busy loops.
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	snap := a.SnapLen
	if snap <= 0 || snap > 65535 {
		snap = 65535
	}
	buf := make([]byte, snap)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, sa, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			a.Stats.Errors.Add(1)
			return err
		}
		if n <= 0 {
			continue
		}
		dir := model.DirectionUnknown
		if ll, ok := sa.(*syscall.SockaddrLinklayer); ok {
			if ll.Pkttype == 4 {
				dir = model.DirectionOutbound
			} else {
				dir = model.DirectionInbound
			}
		}
		if a.DirectionFilter != "" && a.DirectionFilter != model.DirectionUnknown && dir != a.DirectionFilter {
			continue
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		a.Stats.Packets.Add(1)
		a.Stats.Bytes.Add(uint64(n))
		select {
		case out <- Frame{Time: time.Now(), Interface: a.Interface, Direction: dir, Data: cp}:
		default:
			a.Stats.Dropped.Add(1)
		}
	}
}

func (a *AFPacket) StatsView() StatsView { return a.Stats.View() }
func (a *AFPacket) Backend() string      { return "af_packet" }
