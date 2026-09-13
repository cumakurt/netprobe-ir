package notifications

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/model"
)

var telegramBaseURL = "https://api.telegram.org"

var hostRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
var telegramTokenRE = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{20,128}$`)
var telegramChatRE = regexp.MustCompile(`^(?:-?[0-9]{1,32}|@[A-Za-z0-9_]{5,64})$`)

type ChannelStats struct {
	Sent         uint64    `json:"sent"`
	Failed       uint64    `json:"failed"`
	Dropped      uint64    `json:"dropped"`
	Deduplicated uint64    `json:"deduplicated"`
	QueueDepth   int       `json:"queue_depth"`
	LastSuccess  time.Time `json:"last_success,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}
type EmailConfig struct {
	Enabled        bool     `json:"enabled"`
	Host           string   `json:"smtp_server"`
	Port           int      `json:"smtp_port"`
	Username       string   `json:"username"`
	Password       string   `json:"password,omitempty"`
	Sender         string   `json:"sender"`
	Recipients     []string `json:"recipients"`
	TLS            bool     `json:"tls"`
	SSL            bool     `json:"ssl"`
	STARTTLS       bool     `json:"starttls"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Severities     []string `json:"severities"`
}
type TelegramConfig struct {
	Enabled        bool     `json:"enabled"`
	BotToken       string   `json:"bot_token,omitempty"`
	ChatID         string   `json:"chat_id"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Severities     []string `json:"severities"`
}
type Settings struct {
	Email           EmailConfig    `json:"email"`
	Telegram        TelegramConfig `json:"telegram"`
	CooldownSeconds int            `json:"cooldown_seconds"`
	MaxRetries      int            `json:"max_retries"`
}
type PublicEmail struct {
	Enabled        bool     `json:"enabled"`
	Host           string   `json:"smtp_server"`
	Port           int      `json:"smtp_port"`
	Username       string   `json:"username"`
	PasswordSet    bool     `json:"password_set"`
	Sender         string   `json:"sender"`
	Recipients     []string `json:"recipients"`
	TLS            bool     `json:"tls"`
	SSL            bool     `json:"ssl"`
	STARTTLS       bool     `json:"starttls"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Severities     []string `json:"severities"`
}
type PublicTelegram struct {
	Enabled        bool     `json:"enabled"`
	BotTokenSet    bool     `json:"bot_token_set"`
	ChatID         string   `json:"chat_id"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Severities     []string `json:"severities"`
}
type PublicSettings struct {
	Email           PublicEmail    `json:"email"`
	Telegram        PublicTelegram `json:"telegram"`
	CooldownSeconds int            `json:"cooldown_seconds"`
	MaxRetries      int            `json:"max_retries"`
	EmailStats      ChannelStats   `json:"email_stats"`
	TelegramStats   ChannelStats   `json:"telegram_stats"`
}

type job struct {
	finding model.SecurityFinding
	channel string
}
type Manager struct {
	mu                                               sync.RWMutex
	path, keyPath                                    string
	settings                                         Settings
	q                                                chan job
	stop                                             chan struct{}
	done                                             chan struct{}
	dedup                                            map[string]time.Time
	emailSent, emailFailed, emailDropped, emailDedup atomic.Uint64
	tgSent, tgFailed, tgDropped, tgDedup             atomic.Uint64
	emailLastSuccess, tgLastSuccess                  time.Time
	emailLastError, tgLastError                      string
}

func Open(dataDir string) (*Manager, error) {
	dir := filepath.Join(dataDir, "notifications")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{path: filepath.Join(dir, "settings.enc"), keyPath: filepath.Join(dir, "settings.key"), q: make(chan job, 256), stop: make(chan struct{}), done: make(chan struct{}), dedup: map[string]time.Time{}}
	m.settings = Settings{CooldownSeconds: 300, MaxRetries: 3}
	m.settings.Email.TimeoutSeconds = 10
	m.settings.Email.Severities = []string{"high", "critical"}
	m.settings.Telegram.TimeoutSeconds = 10
	m.settings.Telegram.Severities = []string{"medium", "high", "critical"}
	if _, err := os.Stat(m.path); err == nil {
		if err = m.load(); err != nil {
			return nil, err
		}
	}
	go m.worker()
	return m, nil
}
func (m *Manager) Close() {
	if m == nil {
		return
	}
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
	}
	<-m.done
}

func validSeverity(s string) bool {
	switch strings.ToLower(s) {
	case "info", "informational", "low", "medium", "high", "critical":
		return true
	}
	return false
}
func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "informational" {
		return "info"
	}
	return s
}
func normalizeSeverities(xs []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		x = normalizeSeverity(x)
		if !validSeverity(x) {
			return nil, fmt.Errorf("invalid severity %q", x)
		}
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one severity required")
	}
	return out, nil
}
func validateHost(h string) error {
	h = strings.TrimSpace(h)
	if h == "" {
		return errors.New("SMTP server required")
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	if !hostRE.MatchString(h) || strings.Contains(h, "..") {
		return errors.New("invalid SMTP server")
	}
	return nil
}
func validateSettings(s Settings) error {
	if s.CooldownSeconds < 0 || s.CooldownSeconds > 86400 {
		return errors.New("cooldown_seconds out of range")
	}
	if s.MaxRetries < 0 || s.MaxRetries > 5 {
		return errors.New("max_retries out of range")
	}
	if s.Email.Enabled {
		if err := validateHost(s.Email.Host); err != nil {
			return err
		}
		if s.Email.Port < 1 || s.Email.Port > 65535 {
			return errors.New("invalid SMTP port")
		}
		if (s.Email.TLS || s.Email.SSL) && s.Email.STARTTLS {
			return errors.New("choose implicit TLS/SSL or STARTTLS, not both")
		}
		if _, err := mail.ParseAddress(s.Email.Sender); err != nil {
			return errors.New("invalid sender address")
		}
		if len(s.Email.Recipients) == 0 {
			return errors.New("at least one recipient required")
		}
		for _, r := range s.Email.Recipients {
			if _, err := mail.ParseAddress(r); err != nil {
				return fmt.Errorf("invalid recipient address")
			}
		}
		if s.Email.TimeoutSeconds < 1 || s.Email.TimeoutSeconds > 120 {
			return errors.New("SMTP timeout out of range")
		}
	}
	if s.Telegram.Enabled {
		tok := strings.TrimSpace(s.Telegram.BotToken)
		chat := strings.TrimSpace(s.Telegram.ChatID)
		if tok == "" {
			return errors.New("Telegram bot token required")
		}
		if !telegramTokenRE.MatchString(tok) {
			return errors.New("invalid Telegram bot token format")
		}
		if !telegramChatRE.MatchString(chat) {
			return errors.New("invalid Telegram chat ID")
		}
		if s.Telegram.TimeoutSeconds < 1 || s.Telegram.TimeoutSeconds > 120 {
			return errors.New("Telegram timeout out of range")
		}
	}
	var err error
	s.Email.Severities, err = normalizeSeverities(s.Email.Severities)
	if err != nil {
		return fmt.Errorf("email severities: %w", err)
	}
	s.Telegram.Severities, err = normalizeSeverities(s.Telegram.Severities)
	if err != nil {
		return fmt.Errorf("telegram severities: %w", err)
	}
	return nil
}

func (m *Manager) Public() PublicSettings {
	m.mu.RLock()
	s := m.settings
	els := m.emailLastSuccess
	tls := m.tgLastSuccess
	ele := m.emailLastError
	tle := m.tgLastError
	m.mu.RUnlock()
	return PublicSettings{Email: PublicEmail{Enabled: s.Email.Enabled, Host: s.Email.Host, Port: s.Email.Port, Username: s.Email.Username, PasswordSet: s.Email.Password != "", Sender: s.Email.Sender, Recipients: append([]string(nil), s.Email.Recipients...), TLS: s.Email.TLS, SSL: s.Email.SSL, STARTTLS: s.Email.STARTTLS, TimeoutSeconds: s.Email.TimeoutSeconds, Severities: append([]string(nil), s.Email.Severities...)}, Telegram: PublicTelegram{Enabled: s.Telegram.Enabled, BotTokenSet: s.Telegram.BotToken != "", ChatID: s.Telegram.ChatID, TimeoutSeconds: s.Telegram.TimeoutSeconds, Severities: append([]string(nil), s.Telegram.Severities...)}, CooldownSeconds: s.CooldownSeconds, MaxRetries: s.MaxRetries, EmailStats: ChannelStats{Sent: m.emailSent.Load(), Failed: m.emailFailed.Load(), Dropped: m.emailDropped.Load(), Deduplicated: m.emailDedup.Load(), QueueDepth: len(m.q), LastSuccess: els, LastError: ele}, TelegramStats: ChannelStats{Sent: m.tgSent.Load(), Failed: m.tgFailed.Load(), Dropped: m.tgDropped.Load(), Deduplicated: m.tgDedup.Load(), QueueDepth: len(m.q), LastSuccess: tls, LastError: tle}}
}
func (m *Manager) RawForTest() Settings { m.mu.RLock(); defer m.mu.RUnlock(); return m.settings }
func (m *Manager) Update(next Settings) error {
	m.mu.Lock()
	old := m.settings
	if next.Email.Password == "" {
		next.Email.Password = old.Email.Password
	}
	if next.Telegram.BotToken == "" {
		next.Telegram.BotToken = old.Telegram.BotToken
	}
	if next.Email.TimeoutSeconds == 0 {
		next.Email.TimeoutSeconds = 10
	}
	if next.Telegram.TimeoutSeconds == 0 {
		next.Telegram.TimeoutSeconds = 10
	}
	if next.CooldownSeconds == 0 {
		next.CooldownSeconds = 300
	}
	if next.MaxRetries == 0 {
		next.MaxRetries = 3
	}
	if err := validateSettings(next); err != nil {
		m.mu.Unlock()
		return err
	}
	m.settings = next
	m.mu.Unlock()
	return m.save()
}

func (m *Manager) key() ([]byte, error) {
	if b, err := os.ReadFile(m.keyPath); err == nil {
		if len(b) != 32 {
			return nil, errors.New("invalid notification key")
		}
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(m.keyPath, b, 0600); err != nil {
		return nil, err
	}
	return b, nil
}
func (m *Manager) save() error {
	m.mu.RLock()
	b, err := json.Marshal(m.settings)
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	k, err := m.key()
	if err != nil {
		return err
	}
	block, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	ct := g.Seal(nil, nonce, b, nil)
	out := append([]byte("NPNE1"), nonce...)
	out = append(out, ct...)
	tmp := m.path + ".tmp"
	if err = os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}
func (m *Manager) load() error {
	b, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	if len(b) < 5 || string(b[:5]) != "NPNE1" {
		return errors.New("invalid encrypted notification settings")
	}
	k, err := m.key()
	if err != nil {
		return err
	}
	block, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(block)
	if len(b) < 5+g.NonceSize() {
		return errors.New("truncated notification settings")
	}
	pt, err := g.Open(nil, b[5:5+g.NonceSize()], b[5+g.NonceSize():], nil)
	if err != nil {
		return errors.New("notification settings authentication failed")
	}
	var s Settings
	if err = json.Unmarshal(pt, &s); err != nil {
		return err
	}
	m.settings = s
	return nil
}

func containsSeverity(xs []string, s string) bool {
	s = normalizeSeverity(s)
	for _, x := range xs {
		if normalizeSeverity(x) == s {
			return true
		}
	}
	return false
}
func (m *Manager) Enqueue(f model.SecurityFinding) {
	if m == nil {
		return
	}
	m.mu.Lock()
	s := m.settings
	cool := time.Duration(s.CooldownSeconds) * time.Second
	now := time.Now()
	// Keep deduplication state bounded even when an attacker generates a very
	// large number of unique alert keys. Expired entries are discarded first;
	// an absolute cap provides a second safety net.
	if len(m.dedup) > 4096 {
		for k, ts := range m.dedup {
			if now.Sub(ts) >= cool {
				delete(m.dedup, k)
			}
		}
		for k := range m.dedup {
			if len(m.dedup) <= 4096 {
				break
			}
			delete(m.dedup, k)
		}
	}
	key := f.RuleID + "|" + f.Source.IP + "|" + f.Destination.IP + "|" + f.Process + "|" + normalizeSeverity(f.Severity)
	if t, ok := m.dedup[key]; ok && time.Since(t) < cool {
		if s.Email.Enabled && containsSeverity(s.Email.Severities, f.Severity) {
			m.emailDedup.Add(1)
		}
		if s.Telegram.Enabled && containsSeverity(s.Telegram.Severities, f.Severity) {
			m.tgDedup.Add(1)
		}
		m.mu.Unlock()
		return
	}
	m.dedup[key] = now
	m.mu.Unlock()
	if s.Email.Enabled && containsSeverity(s.Email.Severities, f.Severity) {
		select {
		case m.q <- job{finding: f, channel: "email"}:
		default:
			m.emailDropped.Add(1)
		}
	}
	if s.Telegram.Enabled && containsSeverity(s.Telegram.Severities, f.Severity) {
		select {
		case m.q <- job{finding: f, channel: "telegram"}:
		default:
			m.tgDropped.Add(1)
		}
	}
}
func (m *Manager) worker() {
	defer close(m.done)
	for {
		select {
		case <-m.stop:
			return
		case j := <-m.q:
			m.deliver(j)
		}
	}
}
func (m *Manager) deliver(j job) {
	m.mu.RLock()
	s := m.settings
	m.mu.RUnlock()
	tries := s.MaxRetries + 1
	var err error
	for i := 0; i < tries; i++ {
		if j.channel == "email" {
			err = m.sendEmail(context.Background(), s.Email, j.finding, false)
		} else {
			err = m.sendTelegram(context.Background(), s.Telegram, j.finding, false)
		}
		if err == nil {
			break
		}
		if i+1 < tries {
			d := time.Second * time.Duration(1<<i)
			select {
			case <-m.stop:
				return
			case <-time.After(d):
			}
		}
	}
	m.mu.Lock()
	if j.channel == "email" {
		if err == nil {
			m.emailSent.Add(1)
			m.emailLastSuccess = time.Now().UTC()
			m.emailLastError = ""
		} else {
			m.emailFailed.Add(1)
			m.emailLastError = safeErr(err)
		}
	} else {
		if err == nil {
			m.tgSent.Add(1)
			m.tgLastSuccess = time.Now().UTC()
			m.tgLastError = ""
		} else {
			m.tgFailed.Add(1)
			m.tgLastError = safeErr(err)
		}
	}
	m.mu.Unlock()
}
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}
func (m *Manager) TestEmail(ctx context.Context) error {
	m.mu.RLock()
	c := m.settings.Email
	m.mu.RUnlock()
	return m.sendEmail(ctx, c, model.SecurityFinding{Severity: "info", RuleID: "NP-TEST", Title: "NetProbe IR test email", Description: "SMTP notification configuration test", Time: time.Now().UTC()}, true)
}
func (m *Manager) TestTelegram(ctx context.Context) error {
	m.mu.RLock()
	c := m.settings.Telegram
	m.mu.RUnlock()
	return m.sendTelegram(ctx, c, model.SecurityFinding{Severity: "info", RuleID: "NP-TEST", Title: "NetProbe IR test message", Description: "Telegram notification configuration test", Time: time.Now().UTC()}, true)
}

func (m *Manager) sendEmail(ctx context.Context, c EmailConfig, f model.SecurityFinding, test bool) error {
	if err := validateHost(c.Host); err != nil {
		return err
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("invalid SMTP port")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	d := net.Dialer{Timeout: timeout}
	baseConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return classifyNet("SMTP server unreachable", err)
	}
	var conn net.Conn = baseConn
	if c.SSL || c.TLS {
		tlsConn := tls.Client(baseConn, &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			_ = baseConn.Close()
			if errors.Is(err, context.DeadlineExceeded) {
				return errors.New("connection timeout")
			}
			return errors.New("TLS handshake failed")
		}
		conn = tlsConn
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return fmt.Errorf("SMTP protocol error: %w", err)
	}
	defer cl.Close()
	if c.STARTTLS {
		ok, _ := cl.Extension("STARTTLS")
		if !ok {
			return errors.New("SMTP server does not support STARTTLS")
		}
		if err = cl.StartTLS(&tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("TLS handshake failed: %w", err)
		}
	}
	if c.Username != "" {
		if err = cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return errors.New("SMTP authentication failed")
		}
	}
	from, err := mail.ParseAddress(c.Sender)
	if err != nil {
		return errors.New("invalid sender address")
	}
	if err = cl.Mail(from.Address); err != nil {
		return fmt.Errorf("sender rejected: %w", err)
	}
	rcpts := make([]string, 0, len(c.Recipients))
	for _, x := range c.Recipients {
		a, e := mail.ParseAddress(x)
		if e != nil {
			return errors.New("invalid recipient address")
		}
		if e = cl.Rcpt(a.Address); e != nil {
			return errors.New("recipient rejected")
		}
		rcpts = append(rcpts, a.Address)
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA rejected: %w", err)
	}
	subject := "[NetProbe IR] " + strings.ToUpper(f.Severity) + " · " + f.Title
	if test {
		subject = "[NetProbe IR] Test Email"
	}
	body := fmt.Sprintf("Time: %s\r\nSeverity: %s\r\nRule: %s\r\nTitle: %s\r\nDescription: %s\r\nSource: %s\r\nDestination: %s\r\n", f.Time.Format(time.RFC3339), f.Severity, f.RuleID, f.Title, f.Description, f.Source.IP, f.Destination.IP)
	msg := []byte("From: " + from.Address + "\r\nTo: " + strings.Join(rcpts, ",") + "\r\nSubject: " + sanitizeHeader(subject) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
	if _, err = w.Write(msg); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
func sanitizeHeader(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }
func classifyNet(prefix string, err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("connection timeout")
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return fmt.Errorf("DNS resolution failed")
	}
	return fmt.Errorf("%s", prefix)
}

func (m *Manager) sendTelegram(ctx context.Context, c TelegramConfig, f model.SecurityFinding, test bool) error {
	if strings.TrimSpace(c.BotToken) == "" {
		return errors.New("invalid Bot Token")
	}
	if strings.TrimSpace(c.ChatID) == "" {
		return errors.New("invalid Chat ID")
	}
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Timeout: timeout}
	text := fmt.Sprintf("NetProbe IR %s\nSeverity: %s\nRule: %s\n%s\n%s → %s", map[bool]string{true: "Test Message", false: "Security Alert"}[test], strings.ToUpper(f.Severity), f.RuleID, f.Title, f.Source.IP, f.Destination.IP)
	form := url.Values{"chat_id": {c.ChatID}, "text": {text}, "disable_web_page_preview": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telegramBaseURL+"/bot"+url.PathEscape(c.BotToken)+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return classifyNet("Telegram API unreachable", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case 200:
		return nil
	case 401, 403:
		return errors.New("Unauthorized / invalid Bot Token")
	case 400:
		return errors.New("invalid Chat ID or request")
	case 429:
		return errors.New("Telegram API rate limited")
	default:
		return fmt.Errorf("Telegram API unreachable (HTTP %d)", resp.StatusCode)
	}
}
