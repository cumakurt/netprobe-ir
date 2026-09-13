package notifications

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netprobe-ir/internal/model"
)

func testSettings(port int) Settings {
	return Settings{CooldownSeconds: 60, MaxRetries: 1, Email: EmailConfig{Enabled: true, Host: "127.0.0.1", Port: port, Sender: "netprobe@example.test", Recipients: []string{"soc@example.test"}, TimeoutSeconds: 2, Severities: []string{"high", "critical"}}, Telegram: TelegramConfig{Enabled: false, TimeoutSeconds: 2, Severities: []string{"medium", "high", "critical"}}}
}

func smtpServer(t *testing.T, authFail bool) (int, <-chan string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	msgs := make(chan string, 4)
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprint(c, "220 localhost ESMTP\r\n")
				r := bufio.NewReader(c)
				var data strings.Builder
				inData := false
				for {
					line, e := r.ReadString('\n')
					if e != nil {
						return
					}
					trim := strings.TrimSpace(line)
					if inData {
						if trim == "." {
							msgs <- data.String()
							fmt.Fprint(c, "250 queued\r\n")
							inData = false
							continue
						}
						data.WriteString(line)
						continue
					}
					u := strings.ToUpper(trim)
					switch {
					case strings.HasPrefix(u, "EHLO"):
						fmt.Fprint(c, "250-localhost\r\n250 AUTH PLAIN\r\n")
					case strings.HasPrefix(u, "AUTH"):
						if authFail {
							fmt.Fprint(c, "535 auth failed\r\n")
						} else {
							fmt.Fprint(c, "235 ok\r\n")
						}
					case strings.HasPrefix(u, "MAIL FROM:"):
						fmt.Fprint(c, "250 ok\r\n")
					case strings.HasPrefix(u, "RCPT TO:"):
						fmt.Fprint(c, "250 ok\r\n")
					case u == "DATA":
						inData = true
						fmt.Fprint(c, "354 end\r\n")
					case u == "QUIT":
						fmt.Fprint(c, "221 bye\r\n")
						return
					default:
						fmt.Fprint(c, "250 ok\r\n")
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, msgs, func() { _ = ln.Close() }
}

func TestEncryptedPersistenceAndMasking(t *testing.T) {
	d := t.TempDir()
	m, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	s := testSettings(2525)
	s.Email.Password = "super-secret"
	s.Telegram.Enabled = true
	s.Telegram.BotToken = "123456:abcdefghijklmnopqrstuvwxyzABCDE12345"
	s.Telegram.ChatID = "42"
	if err = m.Update(s); err != nil {
		t.Fatal(err)
	}
	pub := m.Public()
	if !pub.Email.PasswordSet || !pub.Telegram.BotTokenSet {
		t.Fatalf("mask flags missing %#v", pub)
	}
	b, _ := os.ReadFile(filepath.Join(d, "notifications", "settings.enc"))
	if strings.Contains(string(b), "super-secret") || strings.Contains(string(b), "abcdefghijklmnopqrstuvwxyzABCDE12345") {
		t.Fatal("secret stored in plaintext")
	}
	m.Close()
	m2, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	raw := m2.RawForTest()
	if raw.Email.Password != "super-secret" || raw.Telegram.BotToken != "123456:abcdefghijklmnopqrstuvwxyzABCDE12345" {
		t.Fatal("secret persistence failed")
	}
}

func TestSMTPTestMessage(t *testing.T) {
	port, msgs, closeFn := smtpServer(t, false)
	defer closeFn()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := testSettings(port)
	if err = m.Update(s); err != nil {
		t.Fatal(err)
	}
	if err = m.TestEmail(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-msgs:
		if !strings.Contains(msg, "NetProbe IR") {
			t.Fatal(msg)
		}
	case <-time.After(time.Second):
		t.Fatal("message not received")
	}
}

func TestSMTPAuthFailureRedactsPassword(t *testing.T) {
	port, _, closeFn := smtpServer(t, true)
	defer closeFn()
	m, _ := Open(t.TempDir())
	defer m.Close()
	s := testSettings(port)
	s.Email.Username = "u"
	s.Email.Password = "dont-leak-me"
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	err := m.TestEmail(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authentication") {
		t.Fatalf("unexpected %v", err)
	}
	if strings.Contains(err.Error(), s.Email.Password) {
		t.Fatal("password leaked")
	}
}

func TestTelegramStatusesAndMasking(t *testing.T) {
	old := telegramBaseURL
	defer func() { telegramBaseURL = old }()
	status := http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer ts.Close()
	telegramBaseURL = ts.URL
	m, _ := Open(t.TempDir())
	defer m.Close()
	s := testSettings(2525)
	s.Email.Enabled = false
	s.Telegram = TelegramConfig{Enabled: true, BotToken: "123456:abcdefghijklmnopqrstuvwxyzABCDE12345", ChatID: "42", TimeoutSeconds: 2, Severities: []string{"critical"}}
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	if err := m.TestTelegram(context.Background()); err != nil {
		t.Fatal(err)
	}
	status = http.StatusTooManyRequests
	if err := m.TestTelegram(context.Background()); err == nil || !strings.Contains(strings.ToLower(err.Error()), "rate limited") {
		t.Fatalf("unexpected %v", err)
	}
	if got := fmt.Sprintf("%+v", m.Public()); strings.Contains(got, "123456:abcdefghijklmnopqrstuvwxyzABCDE12345") {
		t.Fatal("token exposed")
	}
}

func TestSeverityValidation(t *testing.T) {
	m, _ := Open(t.TempDir())
	defer m.Close()
	s := testSettings(2525)
	s.Email.Severities = []string{"bogus"}
	if err := m.Update(s); err == nil {
		t.Fatal("expected invalid severity")
	}
}

func TestSMTPTimeoutIsCategorized(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		// Intentionally never send the SMTP banner. The client must time out.
		time.Sleep(2 * time.Second)
	}()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := testSettings(ln.Addr().(*net.TCPAddr).Port)
	s.Email.TimeoutSeconds = 1
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = m.TestEmail(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "timeout") {
		t.Fatalf("expected sanitized timeout, got %v", err)
	}
	if time.Since(start) > 1800*time.Millisecond {
		t.Fatalf("timeout handling took too long: %v", time.Since(start))
	}
}

func TestTelegramTimeoutAndSecretRedaction(t *testing.T) {
	old := telegramBaseURL
	defer func() { telegramBaseURL = old }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	telegramBaseURL = ts.URL
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := testSettings(2525)
	s.Email.Enabled = false
	s.Telegram = TelegramConfig{Enabled: true, BotToken: "123456:abcdefghijklmnopqrstuvwxyzABCDE12345", ChatID: "42", TimeoutSeconds: 1, Severities: []string{"critical"}}
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	err = m.TestTelegram(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "timeout") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if strings.Contains(err.Error(), "abcdefghijklmnopqrstuvwxyzABCDE12345") {
		t.Fatal("telegram token leaked in timeout error")
	}
}

func TestAsyncSeverityRoutingAndDeduplication(t *testing.T) {
	port, msgs, closeFn := smtpServer(t, false)
	defer closeFn()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := testSettings(port)
	s.CooldownSeconds = 60
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	medium := model.SecurityFinding{ID: "m", Severity: "medium", RuleID: "R", Title: "medium", Source: model.Endpoint{IP: "10.0.0.1"}, Destination: model.Endpoint{IP: "10.0.0.2"}}
	m.Enqueue(medium)
	select {
	case <-msgs:
		t.Fatal("medium severity should not route to email")
	case <-time.After(120 * time.Millisecond):
	}
	high := model.SecurityFinding{ID: "h", Severity: "high", RuleID: "R", Title: "high", Source: model.Endpoint{IP: "10.0.0.1"}, Destination: model.Endpoint{IP: "10.0.0.2"}}
	m.Enqueue(high)
	select {
	case <-msgs:
	case <-time.After(2 * time.Second):
		t.Fatal("high severity email not delivered")
	}
	m.Enqueue(high)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if m.Public().EmailStats.Deduplicated >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m.Public().EmailStats.Deduplicated != 1 {
		t.Fatalf("expected one deduplicated email, got %#v", m.Public().EmailStats)
	}
}

func TestConflictingTLSModesRejected(t *testing.T) {
	m, _ := Open(t.TempDir())
	defer m.Close()
	s := testSettings(2525)
	s.Email.SSL = true
	s.Email.STARTTLS = true
	if err := m.Update(s); err == nil {
		t.Fatal("expected SSL+STARTTLS validation failure")
	}
}

func TestSMTPTLSHandshakeFailureIsCategorized(t *testing.T) {
	port, _, closeFn := smtpServer(t, false)
	defer closeFn()
	m, _ := Open(t.TempDir())
	defer m.Close()
	s := testSettings(port)
	s.Email.SSL = true
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	err := m.TestEmail(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "tls handshake failed") {
		t.Fatalf("unexpected TLS error: %v", err)
	}
}

func TestSMTPRecipientRejectedIsCategorized(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		fmt.Fprint(c, "220 localhost ESMTP\r\n")
		r := bufio.NewReader(c)
		for {
			line, e := r.ReadString('\n')
			if e != nil {
				return
			}
			u := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(u, "EHLO"):
				fmt.Fprint(c, "250 localhost\r\n")
			case strings.HasPrefix(u, "MAIL FROM:"):
				fmt.Fprint(c, "250 ok\r\n")
			case strings.HasPrefix(u, "RCPT TO:"):
				fmt.Fprint(c, "550 recipient denied\r\n")
			default:
				fmt.Fprint(c, "250 ok\r\n")
			}
		}
	}()
	m, _ := Open(t.TempDir())
	defer m.Close()
	s := testSettings(ln.Addr().(*net.TCPAddr).Port)
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	err = m.TestEmail(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "recipient rejected") {
		t.Fatalf("unexpected recipient error: %v", err)
	}
}

func TestTelegramInvalidCredentialStatuses(t *testing.T) {
	old := telegramBaseURL
	defer func() { telegramBaseURL = old }()
	status := http.StatusUnauthorized
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer ts.Close()
	telegramBaseURL = ts.URL
	m, _ := Open(t.TempDir())
	defer m.Close()
	s := testSettings(2525)
	s.Email.Enabled = false
	s.Telegram = TelegramConfig{Enabled: true, BotToken: "123456:abcdefghijklmnopqrstuvwxyzABCDE12345", ChatID: "42", TimeoutSeconds: 2, Severities: []string{"critical"}}
	if err := m.Update(s); err != nil {
		t.Fatal(err)
	}
	if err := m.TestTelegram(context.Background()); err == nil || !strings.Contains(strings.ToLower(err.Error()), "unauthorized") {
		t.Fatalf("unauthorized mapping: %v", err)
	}
	status = http.StatusBadRequest
	if err := m.TestTelegram(context.Background()); err == nil || !strings.Contains(strings.ToLower(err.Error()), "chat id") {
		t.Fatalf("chat mapping: %v", err)
	}
}

func TestNotificationQueueIsBounded(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if got, want := cap(m.q), 256; got != want {
		t.Fatalf("notification queue cap=%d want=%d", got, want)
	}
}
