package perflab

import (
	"context"
	"runtime"
	"sort"
	"time"
)

type Result struct {
	Name         string  `json:"name"`
	Iterations   int     `json:"iterations"`
	ElapsedMS    int64   `json:"elapsed_ms"`
	OpsPerSecond float64 `json:"ops_per_second"`
	P50Micros    float64 `json:"p50_us"`
	P95Micros    float64 `json:"p95_us"`
	P99Micros    float64 `json:"p99_us"`
	AllocBytes   uint64  `json:"alloc_bytes"`
	NumGC        uint32  `json:"num_gc"`
	CPUCount     int     `json:"cpu_count"`
}

func Run(ctx context.Context, name string, iterations int, fn func(int)) Result {
	if iterations <= 0 {
		iterations = 10000
	}
	lat := make([]int64, 0, iterations)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	done := 0
	for i := 0; i < iterations; i++ {
		select {
		case <-ctx.Done():
			i = iterations
			continue
		default:
		}
		t := time.Now()
		fn(i)
		lat = append(lat, time.Since(t).Nanoseconds())
		done++
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&m1)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		idx := int(float64(len(lat)-1) * p)
		return float64(lat[idx]) / 1000
	}
	r := Result{Name: name, Iterations: done, ElapsedMS: elapsed.Milliseconds(), P50Micros: pct(.50), P95Micros: pct(.95), P99Micros: pct(.99), AllocBytes: m1.TotalAlloc - m0.TotalAlloc, NumGC: m1.NumGC - m0.NumGC, CPUCount: runtime.NumCPU()}
	if elapsed > 0 {
		r.OpsPerSecond = float64(done) / elapsed.Seconds()
	}
	return r
}
