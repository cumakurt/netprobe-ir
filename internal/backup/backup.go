package backup

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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

type Manifest struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Files     []File    `json:"files"`
}
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func Create(dataDir, dst string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return "", err
	}
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	zw := zip.NewWriter(out)
	m := Manifest{Version: 1, CreatedAt: time.Now().UTC()}
	roots := []string{"auth", "audit", "baseline", "cases", "tuning", "evidence", "notifications", "timeline", "detection-quality", "response", "exporters"}
	for _, root := range roots {
		base := filepath.Join(dataDir, root)
		_ = filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dataDir, p)
			if strings.Contains(rel, "..") {
				return nil
			}
			f, e := os.Open(p)
			if e != nil {
				return nil
			}
			defer f.Close()
			h := sha256.New()
			tee := io.TeeReader(f, h)
			w, e := zw.Create(rel)
			if e != nil {
				return e
			}
			n, e := io.Copy(w, tee)
			if e != nil {
				return e
			}
			m.Files = append(m.Files, File{Path: filepath.ToSlash(rel), Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
			return nil
		})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	mb, _ := json.MarshalIndent(m, "", "  ")
	w, e := zw.Create("manifest.json")
	if e == nil {
		_, e = w.Write(mb)
	}
	if e1 := zw.Close(); e == nil {
		e = e1
	}
	if e1 := out.Close(); e == nil {
		e = e1
	}
	return dst, e
}
func Verify(path string) error {
	zr, e := zip.OpenReader(path)
	if e != nil {
		return e
	}
	defer zr.Close()
	var m Manifest
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
		if f.Name == "manifest.json" {
			r, _ := f.Open()
			b, _ := io.ReadAll(r)
			r.Close()
			if e = json.Unmarshal(b, &m); e != nil {
				return e
			}
		}
	}
	if m.Version == 0 {
		return fmt.Errorf("backup manifest missing")
	}
	for _, x := range m.Files {
		f := files[x.Path]
		if f == nil {
			return fmt.Errorf("backup file missing: %s", x.Path)
		}
		r, e := f.Open()
		if e != nil {
			return e
		}
		h := sha256.New()
		n, e := io.Copy(h, r)
		r.Close()
		if e != nil {
			return e
		}
		if n != x.Size || hex.EncodeToString(h.Sum(nil)) != x.SHA256 {
			return fmt.Errorf("backup integrity failure: %s", x.Path)
		}
	}
	return nil
}
func Restore(path, dataDir string) error {
	if e := Verify(path); e != nil {
		return e
	}
	zr, e := zip.OpenReader(path)
	if e != nil {
		return e
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			continue
		}
		clean := filepath.Clean(f.Name)
		if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") || strings.Contains(clean, "../") {
			return fmt.Errorf("unsafe backup path %q", f.Name)
		}
		dst := filepath.Join(dataDir, clean)
		rel, _ := filepath.Rel(dataDir, dst)
		if strings.HasPrefix(rel, "..") {
			return fmt.Errorf("backup path escape")
		}
		if e = os.MkdirAll(filepath.Dir(dst), 0750); e != nil {
			return e
		}
		r, e := f.Open()
		if e != nil {
			return e
		}
		tmp := dst + ".restore"
		o, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e == nil {
			_, e = io.Copy(o, r)
			_ = o.Close()
		}
		r.Close()
		if e != nil {
			return e
		}
		if e = os.Rename(tmp, dst); e != nil {
			return e
		}
	}
	return nil
}

// Encrypted backup envelope (NPB1) uses AES-256-CTR for streaming confidentiality
// and HMAC-SHA256 over the complete header+ciphertext for encrypt-then-MAC
// authentication. Two independent 256-bit keys are derived with PBKDF2-HMAC-SHA256.
const encryptedMagic = "NPB1"
const defaultEncryptedIterations = 600000

// encryptedIterations is package-scoped so tests can exercise the complete
// envelope/tamper path with a lower work factor under the race detector.
// Production code never changes it and therefore uses the 600,000-iteration default.
var encryptedIterations = defaultEncryptedIterations

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	if iterations < 1 {
		iterations = 1
	}
	var out []byte
	for block := uint32(1); len(out) < keyLen; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], block)
		mac.Write(b[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func IsEncrypted(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 4)
	if _, err = io.ReadFull(f, b); err != nil {
		return false
	}
	return string(b) == encryptedMagic
}

func encryptFile(src, dst, passphrase string) error {
	if len(passphrase) < 12 {
		return fmt.Errorf("backup passphrase must be at least 12 characters")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(salt); err != nil {
		return err
	}
	if _, err = rand.Read(iv); err != nil {
		return err
	}
	keys := pbkdf2SHA256([]byte(passphrase), salt, encryptedIterations, 64)
	encKey, macKey := keys[:32], keys[32:]
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	header := make([]byte, 0, 4+4+16+16)
	header = append(header, []byte(encryptedMagic)...)
	var iter [4]byte
	binary.BigEndian.PutUint32(iter[:], uint32(encryptedIterations))
	header = append(header, iter[:]...)
	header = append(header, salt...)
	header = append(header, iv...)
	if _, err = out.Write(header); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(header)
	buf := make([]byte, 128*1024)
	enc := make([]byte, len(buf))
	for {
		n, re := in.Read(buf)
		if n > 0 {
			stream.XORKeyStream(enc[:n], buf[:n])
			if _, err = out.Write(enc[:n]); err != nil {
				return err
			}
			_, _ = mac.Write(enc[:n])
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			return re
		}
	}
	if _, err = out.Write(mac.Sum(nil)); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func decryptFile(src, dst, passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("backup passphrase required")
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	const hlen = 4 + 4 + 16 + 16
	if st.Size() < hlen+sha256.Size {
		return fmt.Errorf("encrypted backup is truncated")
	}
	header := make([]byte, hlen)
	if _, err = io.ReadFull(f, header); err != nil {
		return err
	}
	if string(header[:4]) != encryptedMagic {
		return fmt.Errorf("not a NetProbe encrypted backup")
	}
	iterations := int(binary.BigEndian.Uint32(header[4:8]))
	if iterations < 50000 || iterations > 5000000 {
		return fmt.Errorf("invalid backup KDF iterations")
	}
	salt, iv := header[8:24], header[24:40]
	keys := pbkdf2SHA256([]byte(passphrase), salt, iterations, 64)
	encKey, macKey := keys[:32], keys[32:]
	cipherLen := st.Size() - hlen - sha256.Size
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(header)
	if _, err = f.Seek(hlen, io.SeekStart); err != nil {
		return err
	}
	if _, err = io.CopyN(mac, f, cipherLen); err != nil {
		return err
	}
	got := make([]byte, sha256.Size)
	if _, err = io.ReadFull(f, got); err != nil {
		return err
	}
	if !hmac.Equal(mac.Sum(nil), got) {
		return fmt.Errorf("encrypted backup authentication failed")
	}
	if _, err = f.Seek(hlen, io.SeekStart); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: io.LimitReader(f, cipherLen)}
	if _, err = io.Copy(out, reader); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func CreateEncrypted(dataDir, dst, passphrase string) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".netprobe-backup-*.zip")
	if err != nil {
		return "", err
	}
	plain := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(plain)
	if _, err = Create(dataDir, plain); err != nil {
		return "", err
	}
	if err = encryptFile(plain, dst, passphrase); err != nil {
		return "", err
	}
	return dst, nil
}
func VerifyEncrypted(path, passphrase string) error {
	tmp, err := os.CreateTemp("", "netprobe-verify-*.zip")
	if err != nil {
		return err
	}
	p := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(p)
	if err = decryptFile(path, p, passphrase); err != nil {
		return err
	}
	return Verify(p)
}
func RestoreEncrypted(path, dataDir, passphrase string) error {
	tmp, err := os.CreateTemp("", "netprobe-restore-*.zip")
	if err != nil {
		return err
	}
	p := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(p)
	if err = decryptFile(path, p, passphrase); err != nil {
		return err
	}
	return Restore(p, dataDir)
}
