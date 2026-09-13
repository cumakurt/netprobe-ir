package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type FileHash struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Manifest struct {
	Version   int        `json:"version"`
	CreatedAt time.Time  `json:"created_at"`
	Files     []FileHash `json:"files"`
	PublicKey string     `json:"public_key,omitempty"`
	Signature string     `json:"signature,omitempty"`
}
type Signer struct {
	keyPath string
	enabled bool
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewSigner(keyPath string, enabled bool) (*Signer, error) {
	s := &Signer{keyPath: keyPath, enabled: enabled}
	if !enabled {
		return s, nil
	}
	if err := s.loadOrCreate(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Signer) loadOrCreate() error {
	if b, err := os.ReadFile(s.keyPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(string(b))
		if err == nil && len(raw) == ed25519.PrivateKeySize {
			s.private = ed25519.PrivateKey(raw)
			s.public = s.private.Public().(ed25519.PublicKey)
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.keyPath), 0700); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err = os.WriteFile(s.keyPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0600); err != nil {
		return err
	}
	s.private = priv
	s.public = pub
	return nil
}
func HashFile(path string) (FileHash, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileHash{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileHash{}, err
	}
	return FileHash{Path: filepath.Base(path), SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}
func (s *Signer) Build(paths []string) (Manifest, []byte, error) {
	var m Manifest
	m.Version = 1
	m.CreatedAt = time.Now().UTC()
	for _, p := range paths {
		fh, e := HashFile(p)
		if e != nil {
			return m, nil, e
		}
		m.Files = append(m.Files, fh)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	if s.enabled {
		m.PublicKey = base64.StdEncoding.EncodeToString(s.public)
	}
	unsigned := m
	m.Signature = ""
	b, e := json.Marshal(unsigned)
	if e != nil {
		return m, nil, e
	}
	if s.enabled {
		m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, b))
	}
	out, e := json.MarshalIndent(m, "", "  ")
	return m, out, e
}
func VerifyManifest(b []byte) error {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	if m.Signature == "" || m.PublicKey == "" {
		return fmt.Errorf("manifest is unsigned")
	}
	pub, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return err
	}
	u := m
	u.Signature = ""
	raw, _ := json.Marshal(u)
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return fmt.Errorf("invalid manifest signature")
	}
	return nil
}

type DetachedSignature struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	SHA256    string    `json:"sha256"`
	PublicKey string    `json:"public_key"`
	Signature string    `json:"signature"`
}

// SignFile creates a portable detached Ed25519 signature over the SHA-256
// digest of a file. The public key is embedded so a deployment can pin it.
func (s *Signer) SignFile(path string) (DetachedSignature, []byte, error) {
	var d DetachedSignature
	if !s.enabled || len(s.private) != ed25519.PrivateKeySize {
		return d, nil, fmt.Errorf("signing is disabled")
	}
	fh, err := HashFile(path)
	if err != nil {
		return d, nil, err
	}
	d = DetachedSignature{Version: 1, CreatedAt: time.Now().UTC(), SHA256: fh.SHA256, PublicKey: base64.StdEncoding.EncodeToString(s.public)}
	digest, _ := hex.DecodeString(fh.SHA256)
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, digest))
	b, err := json.MarshalIndent(d, "", "  ")
	return d, b, err
}

func VerifyDetachedFile(path string, signatureJSON []byte, expectedPublicKey string) error {
	var d DetachedSignature
	if err := json.Unmarshal(signatureJSON, &d); err != nil {
		return err
	}
	fh, err := HashFile(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(fh.SHA256, d.SHA256) {
		return fmt.Errorf("file SHA-256 mismatch")
	}
	if expectedPublicKey != "" && expectedPublicKey != d.PublicKey {
		return fmt.Errorf("signature public key does not match pinned key")
	}
	pub, err := base64.StdEncoding.DecodeString(d.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(d.Signature)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(d.SHA256)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), digest, sig) {
		return fmt.Errorf("invalid detached signature")
	}
	return nil
}

// VerifyManifestFiles verifies both the Ed25519 manifest signature and every
// listed file's SHA-256/size inside baseDir. Manifest paths are restricted to
// simple basenames to prevent traversal during forensic verification.
func VerifyManifestFiles(baseDir string, b []byte) error {
	if err := VerifyManifest(b); err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for _, x := range m.Files {
		if x.Path == "" || filepath.Base(x.Path) != x.Path {
			return fmt.Errorf("unsafe manifest path %q", x.Path)
		}
		fh, err := HashFile(filepath.Join(baseDir, x.Path))
		if err != nil {
			return err
		}
		if fh.Size != x.Size || !strings.EqualFold(fh.SHA256, x.SHA256) {
			return fmt.Errorf("evidence mismatch: %s", x.Path)
		}
	}
	return nil
}
