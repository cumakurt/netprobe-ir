package assetintel

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Source       string `json:"source,omitempty"`
}
type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	PID      int    `json:"pid,omitempty"`
	Process  string `json:"process,omitempty"`
}
type Inventory struct {
	Time         time.Time   `json:"time"`
	Hostname     string      `json:"hostname"`
	OS           string      `json:"os"`
	Architecture string      `json:"architecture"`
	Kernel       string      `json:"kernel,omitempty"`
	Packages     []Package   `json:"packages,omitempty"`
	Listeners    []Listener  `json:"listeners,omitempty"`
	Containers   []Container `json:"containers,omitempty"`
}
type Container struct {
	ID             string `json:"id"`
	Runtime        string `json:"runtime,omitempty"`
	Pod            string `json:"pod,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Image          string `json:"image,omitempty"`
	ImageDigest    string `json:"image_digest,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	Node           string `json:"node,omitempty"`
}

func Current() Inventory {
	h, _ := os.Hostname()
	return Inventory{Time: time.Now().UTC(), Hostname: h, OS: runtime.GOOS, Architecture: runtime.GOARCH, Kernel: readFirst("/proc/sys/kernel/osrelease")}
}
func readFirst(path string) string { b, _ := os.ReadFile(path); return strings.TrimSpace(string(b)) }

// ParseDPKGStatus parses /var/lib/dpkg/status without invoking package-manager commands.
func ParseDPKGStatus(path string) ([]Package, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []Package
	cur := Package{Source: "dpkg"}
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = Package{Source: "dpkg"}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "Package: ") {
			cur.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		}
		if strings.HasPrefix(line, "Version: ") {
			cur.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}
		if strings.HasPrefix(line, "Architecture: ") {
			cur.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture: "))
		}
	}
	flush()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, sc.Err()
}
func CycloneDX(inv Inventory) map[string]any {
	components := make([]map[string]any, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		components = append(components, map[string]any{"type": "library", "name": p.Name, "version": p.Version, "properties": []map[string]string{{"name": "netprobe:package_source", "value": p.Source}, {"name": "netprobe:architecture", "value": p.Architecture}}})
	}
	return map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": map[string]any{"timestamp": inv.Time.Format(time.RFC3339), "component": map[string]any{"type": "device", "name": inv.Hostname}}, "components": components}
}
func SPDX(inv Inventory) map[string]any {
	pkgs := make([]map[string]any, 0, len(inv.Packages))
	for i, p := range inv.Packages {
		pkgs = append(pkgs, map[string]any{"SPDXID": "SPDXRef-Package-" + strings.ReplaceAll(p.Name, "_", "-"), "name": p.Name, "versionInfo": p.Version, "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "supplier": "NOASSERTION", "packageFileName": p.Source, "primaryPackagePurpose": "LIBRARY", "index": i})
	}
	return map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "NetProbe IR asset inventory - " + inv.Hostname, "creationInfo": map[string]any{"created": inv.Time.Format(time.RFC3339), "creators": []string{"Tool: NetProbe IR"}}, "packages": pkgs}
}
func Marshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
