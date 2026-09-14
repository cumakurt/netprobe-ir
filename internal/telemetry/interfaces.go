package telemetry

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type InterfaceCounters struct {
	RX        Count  `json:"rx"`
	TX        Count  `json:"tx"`
	ErrorsRX  uint64 `json:"errors_rx"`
	ErrorsTX  uint64 `json:"errors_tx"`
	DroppedRX uint64 `json:"dropped_rx"`
	DroppedTX uint64 `json:"dropped_tx"`
}

// ReadInterfaces reads Linux device counters, which include traffic outside the
// capture filter. Missing/non-Linux sources return nil, not invented zeroes.
func ReadInterfaces() map[string]InterfaceCounters {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseInterfaces(bufio.NewScanner(f))
}
func parseInterfaces(sc *bufio.Scanner) map[string]InterfaceCounters {
	out := map[string]InterfaceCounters{}
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			continue
		}
		var values [16]uint64
		valid := true
		for i := range values {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				valid = false
				break
			}
			values[i] = v
		}
		if !valid {
			continue
		}
		out[strings.TrimSpace(name)] = InterfaceCounters{RX: Count{Bytes: values[0], Packets: values[1]}, TX: Count{Bytes: values[8], Packets: values[9]}, ErrorsRX: values[2], DroppedRX: values[3], ErrorsTX: values[10], DroppedTX: values[11]}
	}
	if sc.Err() != nil {
		return nil
	}
	return out
}
