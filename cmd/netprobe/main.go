package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"netprobe-ir/internal/assetintel"
	"netprobe-ir/internal/audit"
	authpkg "netprobe-ir/internal/auth"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/coreebpf"
	"netprobe-ir/internal/detectionlab"
	"netprobe-ir/internal/evidence"
	"netprobe-ir/internal/federation"
	"netprobe-ir/internal/oidc"
	"netprobe-ir/internal/perflab"
	"netprobe-ir/internal/pipeline"
	"netprobe-ir/internal/report"
	"netprobe-ir/internal/ruleimport"
	"netprobe-ir/internal/selftest"
	"netprobe-ir/internal/server"
	"netprobe-ir/internal/sigma"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

const developer = "Cuma KURT"
const developerEmail = "cumakurt@gmail.com"
const projectRepository = "https://github.com/cumakurt/netprobe-ir"
const developerLinkedIn = "https://www.linkedin.com/in/cuma-kurt-34414917/"
const projectLicense = "GNU GPLv3 (GPL-3.0-only)"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, x := range strings.Split(v, ",") {
		x = strings.TrimSpace(x)
		if x != "" {
			*s = append(*s, x)
		}
	}
	return nil
}

func runSigmaCommand(args []string) {
	fs := flag.NewFlagSet("sigma", flag.ExitOnError)
	var in, out, format string
	var correlation bool
	fs.StringVar(&in, "in", "", "input Sigma rule file")
	fs.StringVar(&out, "out", "", "optional output file")
	fs.StringVar(&format, "format", "query", "output format: query or npdl")
	fs.BoolVar(&correlation, "correlation", false, "parse a Sigma correlation rule")
	_ = fs.Parse(args)
	if strings.TrimSpace(in) == "" {
		log.Fatal("sigma: --in is required")
	}
	if correlation {
		f, err := os.Open(in)
		if err != nil {
			log.Fatalf("sigma: %v", err)
		}
		defer f.Close()
		c, err := sigma.ParseCorrelation(f)
		if err != nil {
			log.Fatalf("sigma: %v", err)
		}
		b, _ := json.MarshalIndent(map[string]any{"correlation": c, "plan": sigma.CompileCorrelation(c)}, "", "  ")
		if out == "" {
			fmt.Println(string(b))
			return
		}
		if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
			log.Fatalf("sigma: write output: %v", err)
		}
		return
	}
	r, err := sigma.ParseFile(in)
	if err != nil {
		log.Fatalf("sigma: %v", err)
	}
	var result string
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "query":
		c := sigma.CompileQuery(r)
		result = c.Query + "\n"
	case "npdl":
		result = sigma.RenderNPDL(r)
	default:
		log.Fatalf("sigma: unsupported format %q", format)
	}
	if out == "" {
		fmt.Print(result)
		return
	}
	if err := os.WriteFile(out, []byte(result), 0o644); err != nil {
		log.Fatalf("sigma: write output: %v", err)
	}
}

func runBenchmarkCommand(args []string) {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	iterations := fs.Int("iterations", 100000, "synthetic hot-path iterations")
	_ = fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	x := uint64(0)
	r := perflab.Run(ctx, "synthetic-security-hotpath", *iterations, func(i int) { x ^= uint64(i) * 2654435761; x = (x << 7) | (x >> 57) })
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"result": r, "checksum": x})
}

func runSBOMCommand(args []string) {
	fs := flag.NewFlagSet("sbom", flag.ExitOnError)
	format := fs.String("format", "cyclonedx", "cyclonedx or spdx")
	status := fs.String("dpkg-status", "/var/lib/dpkg/status", "dpkg status file")
	out := fs.String("out", "", "output file (default stdout)")
	_ = fs.Parse(args)
	inv := assetintel.Current()
	if xs, err := assetintel.ParseDPKGStatus(*status); err == nil {
		inv.Packages = xs
	}
	var doc any
	switch strings.ToLower(*format) {
	case "cyclonedx", "cdx":
		doc = assetintel.CycloneDX(inv)
	case "spdx":
		doc = assetintel.SPDX(inv)
	default:
		log.Fatalf("sbom: unsupported format %q", *format)
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	b = append(b, '\n')
	if *out == "" {
		_, _ = os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(*out, b, 0644); err != nil {
		log.Fatalf("sbom: %v", err)
	}
}

func runImportRuleCommand(args []string) {
	fs := flag.NewFlagSet("import-rule", flag.ExitOnError)
	line := fs.String("rule", "", "Suricata/Snort rule line")
	file := fs.String("file", "", "file containing one rule per line")
	_ = fs.Parse(args)
	var lines []string
	if strings.TrimSpace(*line) != "" {
		lines = append(lines, *line)
	}
	if *file != "" {
		b, err := os.ReadFile(*file)
		if err != nil {
			log.Fatalf("import-rule: %v", err)
		}
		for _, x := range strings.Split(string(b), "\n") {
			x = strings.TrimSpace(x)
			if x != "" && !strings.HasPrefix(x, "#") {
				lines = append(lines, x)
			}
		}
	}
	if len(lines) == 0 {
		log.Fatal("import-rule: --rule or --file required")
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for _, x := range lines {
		r, err := ruleimport.ParseLine(x)
		if err != nil {
			_ = enc.Encode(map[string]any{"error": err.Error(), "source": x})
			continue
		}
		_ = enc.Encode(map[string]any{"parsed": r, "translated": ruleimport.Translate(r)})
	}
}

func runEBPFCoreCommand(args []string) {
	fs := flag.NewFlagSet("ebpf-core", flag.ExitOnError)
	source := fs.String("source", "bpf/netprobe_runtime.bpf.c", "CO-RE C source")
	object := fs.String("object", "dist/bpf/netprobe_runtime.bpf.o", "output object")
	build := fs.Bool("build", false, "compile the CO-RE object")
	_ = fs.Parse(args)
	if *build {
		if err := coreebpf.Build(*source, *object); err != nil {
			log.Fatalf("ebpf-core: %v", err)
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(coreebpf.Probe(*object))
}

func fileDigest(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "auth" {
		runAuthCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "config" {
		runConfigCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "replay" {
		runReplayCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "rules" {
		runRulesCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "sigma" {
		runSigmaCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "benchmark" {
		runBenchmarkCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "sbom" {
		runSBOMCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "import-rule" {
		runImportRuleCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "ebpf-core" {
		runEBPFCoreCommand(os.Args[2:])
		return
	}
	var cfgPath, listen, dataDir, authToken, tlsCert, tlsKey string
	var ifaces stringList
	var showVersion, showAbout, runSelf, disableRecorder bool
	flag.StringVar(&cfgPath, "config", "", "JSON configuration file")
	flag.StringVar(&listen, "listen", "", "web listen address override, e.g. 127.0.0.1:8443")
	flag.Var(&ifaces, "interface", "capture interface; repeat or comma-separate; default: all UP interfaces")
	flag.StringVar(&dataDir, "data-dir", "", "data directory override")
	flag.StringVar(&authToken, "auth-token", "", "legacy/API bearer token override")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS certificate path")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS private key path")
	flag.BoolVar(&disableRecorder, "no-recorder", false, "disable PCAPNG flight recorder")
	flag.BoolVar(&runSelf, "self-test", false, "run dependency-free functional self-test and exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&showAbout, "about", false, "print project, developer and license information and exit")
	flag.Parse()
	if showVersion {
		fmt.Printf("NetProbe IR %s commit=%s built=%s go=%s\n", version, commit, buildDate, runtime.Version())
		return
	}
	if showAbout {
		fmt.Printf("NetProbe IR %s\n", version)
		fmt.Printf("Developer: %s <%s>\n", developer, developerEmail)
		fmt.Printf("LinkedIn: %s\n", developerLinkedIn)
		fmt.Printf("Repository: %s\n", projectRepository)
		fmt.Printf("License: %s\n", projectLicense)
		fmt.Printf("Build: commit=%s built=%s go=%s\n", commit, buildDate, runtime.Version())
		return
	}
	if runSelf {
		rs := selftest.Run()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rs)
		for _, r := range rs {
			if !r.OK {
				os.Exit(1)
			}
		}
		return
	}
	c, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if listen != "" {
		c.Listen = listen
	}
	if dataDir != "" {
		c.DataDir = dataDir
	}
	if authToken != "" {
		c.AuthToken = authToken
	}
	if len(ifaces) > 0 {
		c.Interfaces = ifaces
	}
	if disableRecorder {
		c.Recorder.Enabled = false
	}
	if c.Security.RequireSignedConfig {
		if cfgPath == "" {
			log.Fatalf("signed config enforcement requires --config")
		}
		sig := c.Security.ConfigSignature
		if sig == "" {
			sig = cfgPath + ".sig.json"
		} else if !filepath.IsAbs(sig) {
			sig = filepath.Join(filepath.Dir(cfgPath), sig)
		}
		b, er := os.ReadFile(sig)
		if er != nil {
			log.Fatalf("config signature: %v", er)
		}
		if er = evidence.VerifyDetachedFile(cfgPath, b, c.Security.ConfigTrustedPublicKey); er != nil {
			log.Fatalf("config signature verification failed: %v", er)
		}
	}
	if err := c.Prepare(); err != nil {
		log.Fatalf("configuration rejected: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	eng := pipeline.New(c)
	if err := eng.Start(ctx); err != nil {
		log.Fatalf("engine: %v", err)
	}
	ac := authpkg.Config{Enabled: c.Auth.Enabled, DefaultUsername: c.Auth.DefaultUsername, SessionIdle: time.Duration(c.Auth.SessionIdleMinutes) * time.Minute, SessionAbsolute: time.Duration(c.Auth.SessionAbsoluteHours) * time.Hour, MaxFailures: c.Auth.MaxFailures, Lockout: time.Duration(c.Auth.LockoutSeconds) * time.Second, PasswordIterations: c.Auth.PasswordIterations, PasswordMinLength: c.Auth.PasswordMinLength, RequirePasswordChange: c.Auth.RequirePasswordChange}
	am, err := authpkg.New(filepath.Join(c.DataDir, "auth", "users.json"), ac)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	al, err := audit.New(filepath.Join(c.DataDir, "audit", "audit.jsonl"))
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	oc := oidc.New(oidc.Config{Enabled: c.OIDC.Enabled, Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, ClientSecret: c.OIDC.ClientSecret, RedirectURL: c.OIDC.RedirectURL, DefaultRole: c.OIDC.DefaultRole, UsernameClaim: c.OIDC.UsernameClaim, Scopes: c.OIDC.Scopes})
	srv := server.NewSecure(eng, c.AuthToken, am, al, oc)
	httpSrv := &http.Server{Addr: c.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		var e error
		if tlsCert != "" || tlsKey != "" {
			if tlsCert == "" || tlsKey == "" {
				e = fmt.Errorf("both --tls-cert and --tls-key are required")
			} else {
				e = httpSrv.ListenAndServeTLS(tlsCert, tlsKey)
			}
		} else {
			e = httpSrv.ListenAndServe()
		}
		if e != nil && e != http.ErrServerClosed {
			log.Printf("web server: %v", e)
			cancel()
		}
	}()
	if c.Federation.ControllerURL != "" && c.Federation.SensorID != "" {
		host, _ := os.Hostname()
		fc := &federation.Client{URL: c.Federation.ControllerURL, Token: c.Federation.SensorToken, SensorID: c.Federation.SensorID, Hostname: host, Interval: time.Duration(c.Federation.IntervalSeconds) * time.Second, Snapshot: func() federation.Snapshot {
			s := eng.SensorSnapshot(c.Federation.SensorID, host)
			s.Version = version
			s.ConfigSHA256 = fileDigest(cfgPath)
			s.RulesSHA256 = fileDigest(c.IDS.RulesFile)
			return s
		}}
		fc.HandleCommand = func(_ context.Context, cmd federation.FleetCommand) (string, error) {
			switch cmd.Type {
			case "capture_start":
				return "capture started", eng.StartCapture()
			case "capture_stop":
				return "capture stopped", eng.StopCapture()
			case "interface_start", "interface_stop":
				name, _ := cmd.Payload["interface"].(string)
				if strings.TrimSpace(name) == "" {
					return "", fmt.Errorf("interface required")
				}
				if cmd.Type == "interface_start" {
					return "interface started", eng.StartInterface(name)
				}
				return "interface stopped", eng.StopInterface(name)
			case "self_protection_rebaseline":
				if eng.SelfProtect == nil {
					return "", fmt.Errorf("self-protection unavailable")
				}
				return "baseline refreshed", eng.SelfProtect.Rebaseline(c.SelfProtection.Paths)
			case "config_stage", "rules_stage":
				content, _ := cmd.Payload["content"].(string)
				want, _ := cmd.Payload["sha256"].(string)
				if content == "" || want == "" {
					return "", fmt.Errorf("content and sha256 required")
				}
				h := sha256.Sum256([]byte(content))
				if !strings.EqualFold(hex.EncodeToString(h[:]), strings.TrimSpace(want)) {
					return "", fmt.Errorf("SHA-256 mismatch")
				}
				dir := filepath.Join(c.DataDir, "fleet")
				if err := os.MkdirAll(dir, 0750); err != nil {
					return "", err
				}
				name := "staged-config.json"
				if cmd.Type == "rules_stage" {
					name = "staged-rules.json"
				}
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(content), 0640); err != nil {
					return "", err
				}
				return "verified payload staged at " + path, nil
			case "version_report":
				return "NetProbe IR " + version, nil
			default:
				return "", fmt.Errorf("unsupported fleet command %q", cmd.Type)
			}
		}
		go fc.Run(ctx)
	}
	scheme := "http"
	if tlsCert != "" && tlsKey != "" {
		scheme = "https"
	}
	if pw := am.InitialPassword(); pw != "" {
		log.Printf("INITIAL ADMIN USERNAME: %s", c.Auth.DefaultUsername)
		log.Printf("INITIAL ADMIN PASSWORD: %s", pw)
		log.Printf("SECURITY: change this password immediately after first login")
	}
	log.Printf("NetProbe IR %s started: %s://%s", version, scheme, c.Listen)
	log.Printf("capture interfaces: %v", func() []string {
		if len(c.Interfaces) > 0 {
			return c.Interfaces
		}
		return pipeline.DiscoverInterfaces()
	}())
	log.Printf("data directory: %s", c.DataDir)
	<-ctx.Done()
	sdctx, sdcancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = httpSrv.Shutdown(sdctx)
	sdcancel()
	if eng.Baseline != nil {
		_ = eng.Baseline.Flush()
	}
	writeFinalReports(c.DataDir, eng)
	log.Printf("shutdown complete")
}
func writeFinalReports(dataDir string, e *pipeline.Engine) {
	d := report.Data{GeneratedAt: time.Now(), Status: e.Status(), Flows: e.Flows(5000), Alerts: e.Alerts(5000), SecurityFindings: e.Findings(5000), CaptureHealth: e.CaptureHealth()}
	stamp := time.Now().Format("20060102-150405")
	dir := filepath.Join(dataDir, "reports")
	_ = os.MkdirAll(dir, 0750)
	if b, err := report.JSON(d); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "report-"+stamp+".json"), b, 0640)
	}
	if b, err := report.HTML(d); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "report-"+stamp+".html"), b, 0640)
	}
}

func runConfigCommand(args []string) {
	if len(args) < 1 || (args[0] != "sign" && args[0] != "verify") {
		fmt.Fprintln(os.Stderr, "Usage: netprobe config sign|verify [options] config.json")
		os.Exit(2)
	}
	action := args[0]
	fs := flag.NewFlagSet("netprobe config "+action, flag.ExitOnError)
	sig := fs.String("signature", "", "detached signature path")
	pub := fs.String("public-key", "", "expected base64 Ed25519 public key")
	dataDir := fs.String("data-dir", "/var/lib/netprobe-ir", "data directory holding evidence signing key")
	_ = fs.Parse(args[1:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "config JSON file required")
		os.Exit(2)
	}
	path := fs.Arg(0)
	if *sig == "" {
		*sig = path + ".sig.json"
	}
	if action == "verify" {
		b, e := os.ReadFile(*sig)
		if e != nil {
			log.Fatalf("signature: %v", e)
		}
		if e = evidence.VerifyDetachedFile(path, b, *pub); e != nil {
			log.Fatalf("verify: %v", e)
		}
		fmt.Printf("OK: %s verified with %s\n", path, *sig)
		return
	}
	signer, e := evidence.NewSigner(filepath.Join(*dataDir, "evidence", "ed25519.key"), true)
	if e != nil {
		log.Fatalf("signer: %v", e)
	}
	d, b, e := signer.SignFile(path)
	if e != nil {
		log.Fatalf("sign: %v", e)
	}
	if e = os.WriteFile(*sig, b, 0640); e != nil {
		log.Fatalf("write signature: %v", e)
	}
	fmt.Printf("Signed: %s\nSignature: %s\nPublic key: %s\nSHA-256: %s\n", path, *sig, d.PublicKey, d.SHA256)
}

func runAuthCommand(args []string) {
	if len(args) < 1 || (args[0] != "bootstrap" && args[0] != "reset") {
		fmt.Fprintln(os.Stderr, "Usage: netprobe auth bootstrap|reset [--data-dir dir] [--username admin] [--password value]")
		os.Exit(2)
	}
	action := args[0]
	fs := flag.NewFlagSet("netprobe auth "+action, flag.ExitOnError)
	dataDir := fs.String("data-dir", "/var/lib/netprobe-ir", "data directory")
	user := fs.String("username", "admin", "administrator username")
	password := fs.String("password", "", "new password for reset; omit to generate a random one")
	_ = fs.Parse(args[1:])
	cfg := authpkg.DefaultConfig()
	cfg.Enabled = true
	cfg.DefaultUsername = *user
	m, err := authpkg.New(filepath.Join(*dataDir, "auth", "users.json"), cfg)
	if err != nil {
		log.Fatalf("auth %s: %v", action, err)
	}
	if action == "bootstrap" {
		pw := m.InitialPassword()
		if pw == "" {
			fmt.Printf("Authentication store already initialized at %s\n", filepath.Join(*dataDir, "auth", "users.json"))
			return
		}
		fmt.Printf("Username: %s\nInitial password: %s\nPassword change required on first login.\n", *user, pw)
		return
	}
	var pw string
	if *password != "" {
		err = m.AdminResetPassword(*user, *password, true)
		pw = *password
	} else {
		pw, err = m.GenerateResetPassword(*user, true)
	}
	if err != nil {
		log.Fatalf("auth reset: %v", err)
	}
	fmt.Printf("Username: %s\nTemporary password: %s\nPassword change required on next login.\n", *user, pw)
}

func runReplayCommand(args []string) {
	fs := flag.NewFlagSet("netprobe replay", flag.ExitOnError)
	var cfgPath, dataDir string
	fs.StringVar(&cfgPath, "config", "", "JSON configuration file")
	fs.StringVar(&dataDir, "data-dir", "", "data directory for replay results")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: netprobe replay [--config file] [--data-dir dir] capture.pcap[ng]")
		os.Exit(2)
	}
	c, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if dataDir != "" {
		c.DataDir = dataDir
	} else {
		c.DataDir = filepath.Join(os.TempDir(), "netprobe-ir-replay-"+time.Now().Format("20060102-150405"))
	}
	c.Interfaces = nil
	c.Recorder.Enabled = false
	if err = c.Prepare(); err != nil {
		log.Fatalf("configuration: %v", err)
	}
	eng := pipeline.New(c)
	st, err := eng.ReplayFile(fs.Arg(0))
	if err != nil {
		log.Fatalf("replay: %v", err)
	}
	if eng.Baseline != nil {
		_ = eng.Baseline.Flush()
	}
	writeFinalReports(c.DataDir, eng)
	out := map[string]any{"ok": true, "capture": fs.Arg(0), "replay": st, "status": eng.Status(), "findings": eng.Findings(5000), "report_dir": filepath.Join(c.DataDir, "reports")}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func runRulesCommand(args []string) {
	if len(args) < 1 || (args[0] != "sign" && args[0] != "verify" && args[0] != "test") {
		fmt.Fprintln(os.Stderr, "Usage: netprobe rules sign|verify|test [options] rules.json")
		os.Exit(2)
	}
	action := args[0]
	fs := flag.NewFlagSet("netprobe rules "+action, flag.ExitOnError)
	var cfgPath, sigPath, publicKey, pcapPath string
	var expected stringList
	var minFindings int
	fs.StringVar(&cfgPath, "config", "", "JSON configuration file")
	fs.StringVar(&sigPath, "signature", "", "detached signature path (default rules.json.sig.json)")
	fs.StringVar(&publicKey, "public-key", "", "expected base64 Ed25519 public key (verify)")
	fs.StringVar(&pcapPath, "pcap", "", "PCAP/PCAPNG capture used by rules test")
	fs.Var(&expected, "expect-rule", "rule ID expected to match; repeat or comma-separate")
	fs.IntVar(&minFindings, "min-findings", 0, "minimum total findings required for a successful test")
	_ = fs.Parse(args[1:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "a rule-pack JSON file is required")
		os.Exit(2)
	}
	rulePath := fs.Arg(0)
	if action == "test" {
		if pcapPath == "" {
			fmt.Fprintln(os.Stderr, "--pcap is required for rules test")
			os.Exit(2)
		}
		c, err := config.Load(cfgPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		r, err := detectionlab.Run(c, pcapPath, rulePath, "")
		if err != nil {
			log.Fatalf("rules test: %v", err)
		}
		pass := r.Findings >= minFindings
		missing := []string{}
		for _, id := range expected {
			if r.ByRule[id] == 0 {
				pass = false
				missing = append(missing, id)
			}
		}
		out := map[string]any{"ok": pass, "result": r, "expected_rules": expected, "missing_rules": missing, "min_findings": minFindings}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		if !pass {
			os.Exit(1)
		}
		return
	}
	if sigPath == "" {
		sigPath = rulePath + ".sig.json"
	}
	if action == "verify" {
		b, err := os.ReadFile(sigPath)
		if err != nil {
			log.Fatalf("signature: %v", err)
		}
		if err := evidence.VerifyDetachedFile(rulePath, b, publicKey); err != nil {
			log.Fatalf("verify: %v", err)
		}
		fmt.Printf("OK: %s verified with %s\n", rulePath, sigPath)
		return
	}
	c, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := c.Prepare(); err != nil {
		log.Fatalf("configuration: %v", err)
	}
	signer, err := evidence.NewSigner(filepath.Join(c.DataDir, "evidence", "ed25519.key"), true)
	if err != nil {
		log.Fatalf("signer: %v", err)
	}
	d, b, err := signer.SignFile(rulePath)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	if err := os.WriteFile(sigPath, b, 0640); err != nil {
		log.Fatalf("write signature: %v", err)
	}
	fmt.Printf("Signed: %s\nSignature: %s\nPublic key: %s\nSHA-256: %s\n", rulePath, sigPath, d.PublicKey, d.SHA256)
}
