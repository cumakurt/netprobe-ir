package coreebpf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Capability struct {
	Linux         bool   `json:"linux"`
	BTF           bool   `json:"btf"`
	BPFTool       bool   `json:"bpftool"`
	Clang         bool   `json:"clang"`
	ObjectPresent bool   `json:"object_present"`
	Ready         bool   `json:"ready"`
	Reason        string `json:"reason,omitempty"`
	ObjectPath    string `json:"object_path,omitempty"`
}

func Probe(objectPath string) Capability {
	c := Capability{Linux: runtime.GOOS == "linux", ObjectPath: objectPath}
	if !c.Linux {
		c.Reason = "Linux required"
		return c
	}
	if st, e := os.Stat("/sys/kernel/btf/vmlinux"); e == nil && !st.IsDir() {
		c.BTF = true
	}
	if _, e := exec.LookPath("bpftool"); e == nil {
		c.BPFTool = true
	}
	if _, e := exec.LookPath("clang"); e == nil {
		c.Clang = true
	}
	if objectPath != "" {
		if st, e := os.Stat(objectPath); e == nil && st.Size() > 0 {
			c.ObjectPresent = true
		}
	}
	c.Ready = c.BTF && c.BPFTool && c.ObjectPresent
	if !c.Ready {
		var xs []string
		if !c.BTF {
			xs = append(xs, "kernel BTF unavailable")
		}
		if !c.BPFTool {
			xs = append(xs, "bpftool unavailable")
		}
		if !c.ObjectPresent {
			xs = append(xs, "CO-RE object missing")
		}
		c.Reason = strings.Join(xs, ", ")
	}
	return c
}

// Build compiles the shipped CO-RE C source when clang and kernel BTF tooling are available.
// It is deterministic with respect to the source/object paths and does not install anything.
func Build(source, object string) error {
	if source == "" || object == "" {
		return fmt.Errorf("source and object required")
	}
	clang, e := exec.LookPath("clang")
	if e != nil {
		return e
	}
	if err := os.MkdirAll(filepath.Dir(object), 0755); err != nil {
		return err
	}
	cmd := exec.Command(clang, "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-c", source, "-o", object)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("clang BPF build: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
