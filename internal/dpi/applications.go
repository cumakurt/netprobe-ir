package dpi

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

// These rules identify an observed service hostname, never the installed client
// or decrypted content. Shared cloud/CDN infrastructure is labeled as itself.
// DNS questions alone are deliberately not application identity evidence.
var applicationHosts = []struct {
	application string
	domains     []string
}{
	{"YouTube", []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"}},
	{"Netflix", []string{"netflix.com", "nflxvideo.net", "nflximg.net"}},
	{"Spotify", []string{"spotify.com", "scdn.co"}},
	{"WhatsApp", []string{"whatsapp.com", "whatsapp.net"}},
	{"Telegram", []string{"telegram.org", "t.me"}},
	{"Discord", []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net"}},
	{"Zoom", []string{"zoom.us"}},
	{"Microsoft Teams", []string{"teams.microsoft.com", "teams.live.com"}},
	{"Slack", []string{"slack.com", "slack-edge.com"}},
	{"GitHub", []string{"github.com", "githubusercontent.com", "githubassets.com"}},
	{"GitLab", []string{"gitlab.com"}},
	{"Dropbox", []string{"dropbox.com", "dropboxapi.com", "dropboxusercontent.com"}},
	{"Google Drive", []string{"drive.google.com", "drive.usercontent.google.com"}},
	{"OneDrive", []string{"onedrive.live.com", "onedrive.com", "1drv.com"}},
	{"AWS", []string{"amazonaws.com"}},
	{"Azure", []string{"azure.com", "azurewebsites.net", "blob.core.windows.net"}},
	{"Cloudflare", []string{"cloudflare.com", "cloudflare-dns.com"}},
}

func identifyHost(i *model.DPIInfo) {
	host, evidence := "", ""
	if i.TLS != nil && i.TLS.SNI != "" {
		host = i.TLS.SNI
		evidence = "tls_sni"
	} else if i.HTTP != nil && i.HTTP.Host != "" {
		host = i.HTTP.Host
		evidence = "http_host"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	// Do not retain an earlier named service if a persistent HTTP flow changes host.
	if i.MatchedHost != "" {
		i.MatchedHost = ""
		i.Evidence = "payload"
		if i.Protocol == "TLS" {
			i.Application = "HTTPS/TLS"
		} else {
			i.Application = i.Protocol
		}
	}
	if host == "" || strings.ContainsAny(host, " /\\@\r\n") || net.ParseIP(host) != nil {
		return
	}
	for _, rule := range applicationHosts {
		for _, domain := range rule.domains {
			if host == domain || strings.HasSuffix(host, "."+domain) {
				i.Application = rule.application
				i.MatchedHost = host
				i.Evidence = evidence
				return
			}
		}
	}
}
func detectAdditional(p *decode.Packet, b []byte) string {
	if p.Protocol == "UDP" {
		// WireGuard handshake shapes (no port-only or transport-data-only guesses).
		if len(b) == 148 && binary.LittleEndian.Uint32(b[:4]) == 1 && !allZero(b[8:]) {
			return "WireGuard"
		}
		if len(b) == 92 && binary.LittleEndian.Uint32(b[:4]) == 2 && !allZero(b[12:]) {
			return "WireGuard"
		}
	}
	if p.Protocol == "TCP" && len(b) >= 68 && bytes.HasPrefix(b, []byte("\x13BitTorrent protocol")) {
		return "BitTorrent"
	}
	// Greetings are short; do not copy entire retained streams to inspect a line.
	if len(b) > 1024 {
		b = b[:1024]
	}
	first, _, _ := strings.Cut(string(b), "\r\n")
	if strings.HasPrefix(first, "SIP/2.0 ") || (strings.HasSuffix(first, " SIP/2.0") && (strings.HasPrefix(first, "INVITE sip:") || strings.HasPrefix(first, "REGISTER sip:") || strings.HasPrefix(first, "OPTIONS sip:"))) {
		return "SIP"
	}
	if p.Protocol != "TCP" {
		return ""
	}
	upper := strings.ToUpper(first)
	if (p.SrcPort == 25 || p.DstPort == 25 || p.SrcPort == 587 || p.DstPort == 587) && (strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO ") || strings.HasPrefix(upper, "220 ") && strings.Contains(upper, "SMTP")) {
		return "SMTP"
	}
	if (p.SrcPort == 21 || p.DstPort == 21) && strings.HasPrefix(upper, "220 ") && strings.Contains(upper, "FTP") {
		return "FTP"
	}
	if strings.HasPrefix(upper, "* OK ") && strings.Contains(upper, "IMAP") {
		return "IMAP"
	}
	if (p.SrcPort == 110 || p.DstPort == 110) && strings.HasPrefix(upper, "+OK ") && strings.Contains(upper, "POP3") {
		return "POP3"
	}
	return ""
}
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
