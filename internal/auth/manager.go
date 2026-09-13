package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const CookieName = "netprobe_session"

type Config struct {
	Enabled               bool
	DefaultUsername       string
	SessionIdle           time.Duration
	SessionAbsolute       time.Duration
	MaxFailures           int
	Lockout               time.Duration
	PasswordIterations    int
	PasswordMinLength     int
	RequirePasswordChange bool
}

type User struct {
	Username       string    `json:"username"`
	DisplayName    string    `json:"display_name,omitempty"`
	Role           string    `json:"role"`
	PasswordHash   string    `json:"password_hash"`
	PasswordSalt   string    `json:"password_salt"`
	Iterations     int       `json:"iterations"`
	MustChange     bool      `json:"must_change_password"`
	Disabled       bool      `json:"disabled"`
	TOTPSecret     string    `json:"totp_secret,omitempty"`
	TOTPEnabled    bool      `json:"totp_enabled"`
	RecoveryHashes []string  `json:"recovery_hashes,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	LastLoginAt    time.Time `json:"last_login_at,omitempty"`
}

type PublicUser struct {
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name,omitempty"`
	Role        string    `json:"role"`
	MustChange  bool      `json:"must_change_password"`
	Disabled    bool      `json:"disabled"`
	TOTPEnabled bool      `json:"totp_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

type Session struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Role       string    `json:"role"`
	SourceIP   string    `json:"source_ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeen   time.Time `json:"last_seen"`
	ExpiresAt  time.Time `json:"expires_at"`
	AbsoluteAt time.Time `json:"absolute_expires_at"`
	External   bool      `json:"external,omitempty"`
}

type APIToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Scopes    []string  `json:"scopes"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Revoked   bool      `json:"revoked"`
}

type storeFile struct {
	Version int        `json:"version"`
	Users   []User     `json:"users"`
	Tokens  []APIToken `json:"tokens,omitempty"`
}

type failureState struct {
	Count       int
	LockedUntil time.Time
	Last        time.Time
}

type Principal struct {
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	Scopes     []string `json:"scopes,omitempty"`
	SessionID  string   `json:"session_id,omitempty"`
	TokenID    string   `json:"token_id,omitempty"`
	External   bool     `json:"external,omitempty"`
	MustChange bool     `json:"must_change_password,omitempty"`
}

type Manager struct {
	mu              sync.Mutex
	path            string
	cfg             Config
	users           map[string]*User
	sessions        map[string]*Session
	tokens          map[string]*APIToken
	failures        map[string]*failureState
	initialPassword string
}

func DefaultConfig() Config {
	return Config{Enabled: true, DefaultUsername: "admin", SessionIdle: 30 * time.Minute, SessionAbsolute: 12 * time.Hour, MaxFailures: 5, Lockout: 5 * time.Minute, PasswordIterations: 600000, PasswordMinLength: 12, RequirePasswordChange: true}
}

func New(path string, cfg Config) (*Manager, error) {
	d := DefaultConfig()
	if cfg.DefaultUsername == "" {
		cfg.DefaultUsername = d.DefaultUsername
	}
	if cfg.SessionIdle <= 0 {
		cfg.SessionIdle = d.SessionIdle
	}
	if cfg.SessionAbsolute <= 0 {
		cfg.SessionAbsolute = d.SessionAbsolute
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = d.MaxFailures
	}
	if cfg.Lockout <= 0 {
		cfg.Lockout = d.Lockout
	}
	if cfg.PasswordIterations < 50000 {
		cfg.PasswordIterations = d.PasswordIterations
	}
	if cfg.PasswordMinLength < 10 {
		cfg.PasswordMinLength = d.PasswordMinLength
	}
	m := &Manager{path: path, cfg: cfg, users: map[string]*User{}, sessions: map[string]*Session{}, tokens: map[string]*APIToken{}, failures: map[string]*failureState{}}
	if !cfg.Enabled {
		return m, nil
	}
	if err := m.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(m.users) == 0 {
		pw, err := randomPassword(24)
		if err != nil {
			return nil, err
		}
		u, err := m.newUser(cfg.DefaultUsername, "NetProbe Administrator", "admin", pw, cfg.RequirePasswordChange)
		if err != nil {
			return nil, err
		}
		m.users[strings.ToLower(u.Username)] = &u
		m.initialPassword = pw
		if err = m.saveLocked(); err != nil {
			return nil, err
		}
	}
	return m, nil
}
func (m *Manager) Enabled() bool { return m != nil && m.cfg.Enabled }
func (m *Manager) InitialPassword() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.initialPassword
}
func (m *Manager) ClearInitialPassword() { m.mu.Lock(); m.initialPassword = ""; m.mu.Unlock() }

func (m *Manager) load() error {
	b, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	var sf storeFile
	if err = json.Unmarshal(b, &sf); err != nil {
		return err
	}
	for i := range sf.Users {
		u := sf.Users[i]
		m.users[strings.ToLower(u.Username)] = &u
	}
	for i := range sf.Tokens {
		t := sf.Tokens[i]
		m.tokens[t.ID] = &t
	}
	return nil
}
func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0750); err != nil {
		return err
	}
	sf := storeFile{Version: 1}
	for _, u := range m.users {
		sf.Users = append(sf.Users, *u)
	}
	sort.Slice(sf.Users, func(i, j int) bool { return sf.Users[i].Username < sf.Users[j].Username })
	for _, t := range m.tokens {
		sf.Tokens = append(sf.Tokens, *t)
	}
	sort.Slice(sf.Tokens, func(i, j int) bool { return sf.Tokens[i].CreatedAt.Before(sf.Tokens[j].CreatedAt) })
	b, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func normalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func validateRole(r string) bool {
	switch r {
	case "admin", "analyst", "responder", "viewer":
		return true
	}
	return false
}
func (m *Manager) newUser(username, display, role, password string, must bool) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" || strings.ContainsAny(username, "/\\\x00") {
		return User{}, fmt.Errorf("invalid username")
	}
	if !validateRole(role) {
		return User{}, fmt.Errorf("invalid role")
	}
	if err := m.ValidatePassword(password); err != nil {
		return User{}, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return User{}, err
	}
	h := pbkdf2SHA256([]byte(password), salt, m.cfg.PasswordIterations, 32)
	now := time.Now().UTC()
	return User{Username: username, DisplayName: display, Role: role, PasswordHash: base64.RawStdEncoding.EncodeToString(h), PasswordSalt: base64.RawStdEncoding.EncodeToString(salt), Iterations: m.cfg.PasswordIterations, MustChange: must, CreatedAt: now, UpdatedAt: now}, nil
}
func (m *Manager) ValidatePassword(p string) error {
	if len(p) < m.cfg.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", m.cfg.PasswordMinLength)
	}
	var upper, lower, digit, special bool
	for _, r := range p {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			special = true
		}
	}
	if !(upper && lower && digit && special) {
		return fmt.Errorf("password must include upper, lower, digit and special characters")
	}
	return nil
}
func verifyPassword(u *User, p string) bool {
	salt, e := base64.RawStdEncoding.DecodeString(u.PasswordSalt)
	if e != nil {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(u.PasswordHash)
	if e != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(p), salt, u.Iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (m *Manager) Login(username, password, mfa, sourceIP, ua string) (string, Principal, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled {
		return "", Principal{}, false, fmt.Errorf("authentication disabled")
	}
	key := normalizeUsername(username)
	fk := key + "|" + sourceIP
	now := time.Now().UTC()
	fs := m.failures[fk]
	if fs != nil && now.Before(fs.LockedUntil) {
		return "", Principal{}, false, fmt.Errorf("login temporarily locked until %s", fs.LockedUntil.Format(time.RFC3339))
	}
	u := m.users[key]
	if u == nil || u.Disabled || !verifyPassword(u, password) {
		m.failLocked(fk, now)
		return "", Principal{}, false, fmt.Errorf("invalid credentials")
	}
	if u.TOTPEnabled {
		if !m.verifyMFALocked(u, mfa, now) {
			m.failLocked(fk, now)
			return "", Principal{}, false, fmt.Errorf("multi-factor code required or invalid")
		}
	}
	delete(m.failures, fk)
	sid, err := randomToken(32)
	if err != nil {
		return "", Principal{}, false, err
	}
	s := &Session{ID: sid, Username: u.Username, Role: u.Role, SourceIP: sourceIP, UserAgent: ua, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(m.cfg.SessionIdle), AbsoluteAt: now.Add(m.cfg.SessionAbsolute)}
	m.sessions[sid] = s
	u.LastLoginAt = now
	u.UpdatedAt = now
	_ = m.saveLocked()
	return sid, Principal{Username: u.Username, Role: u.Role, SessionID: sid}, u.MustChange, nil
}
func (m *Manager) failLocked(k string, now time.Time) {
	f := m.failures[k]
	if f == nil {
		f = &failureState{}
		m.failures[k] = f
	}
	if now.Sub(f.Last) > 15*time.Minute {
		f.Count = 0
	}
	f.Count++
	f.Last = now
	if f.Count >= m.cfg.MaxFailures {
		f.LockedUntil = now.Add(m.cfg.Lockout)
		f.Count = 0
	}
}
func (m *Manager) verifyMFALocked(u *User, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	if VerifyTOTP(u.TOTPSecret, code, now) {
		return true
	}
	h := sha256.Sum256([]byte(strings.ToUpper(code)))
	hs := hex.EncodeToString(h[:])
	for i, x := range u.RecoveryHashes {
		if subtle.ConstantTimeCompare([]byte(x), []byte(hs)) == 1 {
			u.RecoveryHashes = append(u.RecoveryHashes[:i], u.RecoveryHashes[i+1:]...)
			_ = m.saveLocked()
			return true
		}
	}
	return false
}

// RevalidatePrincipal checks that a principal used by a long-lived connection
// (for example a WebSocket) is still authorized. It deliberately does not
// extend the session idle deadline: an unattended open console must still
// expire according to SessionIdle, while explicit API requests refresh it.
func (m *Manager) RevalidatePrincipal(p Principal) (Principal, error) {
	if m == nil || !m.cfg.Enabled {
		return p, nil
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.SessionID != "" {
		s := m.sessions[p.SessionID]
		if s == nil {
			return Principal{}, fmt.Errorf("session revoked")
		}
		if now.After(s.ExpiresAt) || now.After(s.AbsoluteAt) {
			delete(m.sessions, p.SessionID)
			return Principal{}, fmt.Errorf("session expired")
		}
		if s.External {
			return Principal{Username: s.Username, Role: s.Role, SessionID: s.ID, External: true}, nil
		}
		u := m.users[normalizeUsername(s.Username)]
		if u == nil || u.Disabled {
			delete(m.sessions, p.SessionID)
			return Principal{}, fmt.Errorf("account unavailable")
		}
		return Principal{Username: u.Username, Role: u.Role, SessionID: s.ID, MustChange: u.MustChange}, nil
	}
	if p.TokenID != "" {
		t := m.tokens[p.TokenID]
		if t == nil || t.Revoked || (!t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)) {
			return Principal{}, fmt.Errorf("token revoked or expired")
		}
		u := m.users[normalizeUsername(t.Username)]
		if u == nil || u.Disabled {
			return Principal{}, fmt.Errorf("account unavailable")
		}
		return Principal{Username: t.Username, Role: t.Role, Scopes: append([]string(nil), t.Scopes...), TokenID: t.ID}, nil
	}
	return p, nil
}

func (m *Manager) AuthenticateRequest(r *http.Request, legacyToken string) (Principal, error) {
	if m == nil || !m.cfg.Enabled {
		if legacyToken == "" {
			return Principal{Username: "local", Role: "admin"}, nil
		}
		return authenticateLegacy(r, legacyToken)
	}
	// scoped API tokens and legacy bearer token
	if b := bearer(r); b != "" {
		sum := sha256.Sum256([]byte(b))
		hs := hex.EncodeToString(sum[:])
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, t := range m.tokens {
			if t.Revoked || (!t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)) {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(hs)) == 1 {
				return Principal{Username: t.Username, Role: t.Role, Scopes: append([]string(nil), t.Scopes...), TokenID: t.ID}, nil
			}
		}
		if legacyToken != "" && subtle.ConstantTimeCompare([]byte(b), []byte(legacyToken)) == 1 {
			return Principal{Username: "legacy-token", Role: "admin"}, nil
		}
	}
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return Principal{}, fmt.Errorf("unauthorized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[c.Value]
	if s == nil {
		return Principal{}, fmt.Errorf("unauthorized")
	}
	now := time.Now().UTC()
	if now.After(s.ExpiresAt) || now.After(s.AbsoluteAt) {
		delete(m.sessions, c.Value)
		return Principal{}, fmt.Errorf("session expired")
	}
	if s.External {
		s.LastSeen = now
		s.ExpiresAt = now.Add(m.cfg.SessionIdle)
		return Principal{Username: s.Username, Role: s.Role, SessionID: s.ID, External: true}, nil
	}
	u := m.users[normalizeUsername(s.Username)]
	if u == nil || u.Disabled {
		delete(m.sessions, c.Value)
		return Principal{}, fmt.Errorf("account unavailable")
	}
	s.LastSeen = now
	s.ExpiresAt = now.Add(m.cfg.SessionIdle)
	return Principal{Username: u.Username, Role: u.Role, SessionID: s.ID, External: s.External, MustChange: u.MustChange}, nil
}
func authenticateLegacy(r *http.Request, want string) (Principal, error) {
	tok := bearer(r)
	if tok == "" {
		tok = r.Header.Get("X-NetProbe-Token")
	}
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(want)) != 1 {
		return Principal{}, fmt.Errorf("unauthorized")
	}
	return Principal{Username: "legacy-token", Role: "admin"}, nil
}
func bearer(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(v) > 7 && strings.EqualFold(v[:7], "Bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

func (m *Manager) Logout(sessionID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}
func (m *Manager) ChangePassword(username, current, next string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil {
		return fmt.Errorf("user not found")
	}
	if !verifyPassword(u, current) {
		return fmt.Errorf("current password is incorrect")
	}
	return m.setPasswordLocked(u, next, false)
}
func (m *Manager) setPasswordLocked(u *User, next string, must bool) error {
	if err := m.ValidatePassword(next); err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	h := pbkdf2SHA256([]byte(next), salt, m.cfg.PasswordIterations, 32)
	u.PasswordSalt = base64.RawStdEncoding.EncodeToString(salt)
	u.PasswordHash = base64.RawStdEncoding.EncodeToString(h)
	u.Iterations = m.cfg.PasswordIterations
	u.MustChange = must
	u.UpdatedAt = time.Now().UTC()
	for id, s := range m.sessions {
		if s.Username == u.Username && id != "" {
			delete(m.sessions, id)
		}
	}
	return m.saveLocked()
}
func (m *Manager) AdminResetPassword(username, next string, must bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil {
		return fmt.Errorf("user not found")
	}
	return m.setPasswordLocked(u, next, must)
}
func (m *Manager) GenerateResetPassword(username string, must bool) (string, error) {
	pw, err := randomPassword(24)
	if err != nil {
		return "", err
	}
	if err = m.AdminResetPassword(username, pw, must); err != nil {
		return "", err
	}
	return pw, nil
}
func (m *Manager) CreateUser(username, display, role, password string, must bool) (PublicUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := normalizeUsername(username)
	if _, ok := m.users[k]; ok {
		return PublicUser{}, fmt.Errorf("user exists")
	}
	u, err := m.newUser(username, display, role, password, must)
	if err != nil {
		return PublicUser{}, err
	}
	m.users[k] = &u
	if err = m.saveLocked(); err != nil {
		return PublicUser{}, err
	}
	return public(u), nil
}
func (m *Manager) enabledAdminsLocked() int {
	n := 0
	for _, u := range m.users {
		if u.Role == "admin" && !u.Disabled {
			n++
		}
	}
	return n
}

func (m *Manager) SetRole(username, role string) error {
	if !validateRole(role) {
		return fmt.Errorf("invalid role")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil {
		return fmt.Errorf("user not found")
	}
	if u.Role == "admin" && role != "admin" && !u.Disabled && m.enabledAdminsLocked() <= 1 {
		return fmt.Errorf("cannot remove the last enabled administrator")
	}
	u.Role = role
	u.UpdatedAt = time.Now().UTC()
	for _, s := range m.sessions {
		if s.Username == u.Username {
			s.Role = role
		}
	}
	return m.saveLocked()
}
func (m *Manager) SetDisabled(username string, disabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil {
		return fmt.Errorf("user not found")
	}
	if disabled && u.Role == "admin" && !u.Disabled && m.enabledAdminsLocked() <= 1 {
		return fmt.Errorf("cannot disable the last enabled administrator")
	}
	u.Disabled = disabled
	u.UpdatedAt = time.Now().UTC()
	if disabled {
		for id, s := range m.sessions {
			if s.Username == u.Username {
				delete(m.sessions, id)
			}
		}
	}
	return m.saveLocked()
}
func public(u User) PublicUser {
	return PublicUser{Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, MustChange: u.MustChange, Disabled: u.Disabled, TOTPEnabled: u.TOTPEnabled, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}
func (m *Manager) Users() []PublicUser {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PublicUser, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, public(*u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}
func (m *Manager) User(username string) (PublicUser, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil {
		return PublicUser{}, false
	}
	return public(*u), true
}

func (m *Manager) Sessions(username string) []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var out []Session
	for id, s := range m.sessions {
		if now.After(s.ExpiresAt) || now.After(s.AbsoluteAt) {
			delete(m.sessions, id)
			continue
		}
		if username == "" || s.Username == username {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
func (m *Manager) RevokeSession(requester, targetID string, admin bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[targetID]
	if s == nil {
		return fmt.Errorf("session not found")
	}
	if !admin && s.Username != requester {
		return fmt.Errorf("not permitted")
	}
	delete(m.sessions, targetID)
	return nil
}
func (m *Manager) RevokeOtherSessions(username, keep string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.Username == username && id != keep {
			delete(m.sessions, id)
		}
	}
}

func (m *Manager) SetupTOTP(username, issuer string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil {
		return "", "", fmt.Errorf("user not found")
	}
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	u.TOTPSecret = secret
	u.TOTPEnabled = false
	u.RecoveryHashes = nil
	u.UpdatedAt = time.Now().UTC()
	if err := m.saveLocked(); err != nil {
		return "", "", err
	}
	label := url.QueryEscape(issuer + ":" + u.Username)
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, url.QueryEscape(issuer))
	return secret, uri, nil
}
func (m *Manager) EnableTOTP(username, code string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil || u.TOTPSecret == "" {
		return nil, fmt.Errorf("TOTP setup not started")
	}
	if !VerifyTOTP(u.TOTPSecret, code, time.Now()) {
		return nil, fmt.Errorf("invalid TOTP code")
	}
	codes := make([]string, 10)
	u.RecoveryHashes = nil
	for i := range codes {
		raw, _ := randomPassword(12)
		raw = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(raw, "!", "A"), "@", "B"))
		codes[i] = raw
		h := sha256.Sum256([]byte(raw))
		u.RecoveryHashes = append(u.RecoveryHashes, hex.EncodeToString(h[:]))
	}
	u.TOTPEnabled = true
	u.UpdatedAt = time.Now().UTC()
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return codes, nil
}
func (m *Manager) DisableTOTP(username, password, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[normalizeUsername(username)]
	if u == nil {
		return fmt.Errorf("user not found")
	}
	if !verifyPassword(u, password) {
		return fmt.Errorf("password incorrect")
	}
	if u.TOTPEnabled && !m.verifyMFALocked(u, code, time.Now()) {
		return fmt.Errorf("invalid MFA code")
	}
	u.TOTPEnabled = false
	u.TOTPSecret = ""
	u.RecoveryHashes = nil
	u.UpdatedAt = time.Now().UTC()
	return m.saveLocked()
}

func (m *Manager) CreateToken(username, name, role string, scopes []string, ttl time.Duration) (APIToken, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validateRole(role) {
		return APIToken{}, "", fmt.Errorf("invalid role")
	}
	raw, err := randomToken(32)
	if err != nil {
		return APIToken{}, "", err
	}
	idRaw, _ := randomToken(8)
	sum := sha256.Sum256([]byte(raw))
	t := APIToken{ID: idRaw, Name: strings.TrimSpace(name), Username: username, Role: role, Scopes: unique(scopes), Hash: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC()}
	if ttl > 0 {
		t.ExpiresAt = t.CreatedAt.Add(ttl)
	}
	m.tokens[t.ID] = &t
	if err = m.saveLocked(); err != nil {
		return APIToken{}, "", err
	}
	pub := t
	pub.Hash = ""
	return pub, raw, nil
}
func (m *Manager) Tokens() []APIToken {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []APIToken
	for _, t := range m.tokens {
		v := *t
		v.Hash = ""
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (m *Manager) RevokeToken(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tokens[id]
	if t == nil {
		return fmt.Errorf("token not found")
	}
	t.Revoked = true
	return m.saveLocked()
}

func (m *Manager) CreateExternalSession(username, role, sourceIP, ua string) (string, Principal, error) {
	if !validateRole(role) {
		role = "viewer"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	sid, err := randomToken(32)
	if err != nil {
		return "", Principal{}, err
	}
	s := &Session{ID: sid, Username: username, Role: role, SourceIP: sourceIP, UserAgent: ua, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(m.cfg.SessionIdle), AbsoluteAt: now.Add(m.cfg.SessionAbsolute), External: true}
	m.sessions[sid] = s
	return sid, Principal{Username: username, Role: role, SessionID: sid, External: true}, nil
}

func Can(p Principal, perm string) bool {
	if p.Role == "admin" {
		return true
	}
	if len(p.Scopes) > 0 {
		for _, s := range p.Scopes {
			if s == "*" || s == perm || strings.HasSuffix(s, ":*") && strings.HasPrefix(perm, strings.TrimSuffix(s, "*")) {
				return true
			}
		}
		return false
	}
	switch p.Role {
	case "viewer":
		return strings.HasPrefix(perm, "read:")
	case "analyst":
		return strings.HasPrefix(perm, "read:") || perm == "case:write" || perm == "hunt:run" || perm == "lab:run" || perm == "tuning:write" || perm == "response:request"
	case "responder":
		return strings.HasPrefix(perm, "read:") || perm == "case:write" || perm == "hunt:run" || perm == "capture:control" || perm == "response:execute" || perm == "response:request" || perm == "tuning:write"
	}
	return false
}

func ClientIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}
func SetSessionCookie(w http.ResponseWriter, r *http.Request, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: id, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func VerifyTOTP(secret, code string, now time.Time) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false
	}
	for d := -1; d <= 1; d++ {
		if totpCode(b, now.Add(time.Duration(d)*30*time.Second)) == code {
			return true
		}
	}
	return false
}
func totpCode(key []byte, t time.Time) string {
	counter := uint64(t.Unix() / 30)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(b[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0xf
	v := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", v%1000000)
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		var bi [4]byte
		binary.BigEndian.PutUint32(bi[:], uint32(block))
		mac.Write(bi[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
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
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func randomPassword(n int) (string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
	b := make([]byte, n)
	rb := make([]byte, n)
	if _, e := rand.Read(rb); e != nil {
		return "", e
	}
	for i := range b {
		b[i] = chars[int(rb[i])%len(chars)]
	}
	if n >= 4 {
		b[0] = 'A'
		b[1] = 'a'
		b[2] = '7'
		b[3] = '!'
	}
	return string(b), nil
}
func unique(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
func ParseTTL(s string) time.Duration {
	if s == "" {
		return 0
	}
	if d, e := time.ParseDuration(s); e == nil {
		return d
	}
	if n, e := strconv.Atoi(s); e == nil {
		return time.Duration(n) * time.Second
	}
	return 0
}
