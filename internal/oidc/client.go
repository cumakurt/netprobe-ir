package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled       bool     `json:"enabled"`
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`
	DefaultRole   string   `json:"default_role"`
	UsernameClaim string   `json:"username_claim"`
	Scopes        []string `json:"scopes"`
}
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type jwks struct {
	Keys []jwk `json:"keys"`
}
type pending struct {
	Verifier string
	Nonce    string
	Expires  time.Time
}
type Claims map[string]any
type Client struct {
	cfg     Config
	http    *http.Client
	mu      sync.Mutex
	disc    discovery
	pending map[string]pending
}

func New(c Config) *Client {
	if c.DefaultRole == "" {
		c.DefaultRole = "viewer"
	}
	if c.UsernameClaim == "" {
		c.UsernameClaim = "preferred_username"
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
	return &Client{cfg: c, http: &http.Client{Timeout: 10 * time.Second}, pending: map[string]pending{}}
}
func (c *Client) Enabled() bool {
	return c != nil && c.cfg.Enabled && c.cfg.Issuer != "" && c.cfg.ClientID != ""
}
func (c *Client) discover(ctx context.Context) (discovery, error) {
	c.mu.Lock()
	if c.disc.TokenEndpoint != "" {
		d := c.disc
		c.mu.Unlock()
		return d, nil
	}
	c.mu.Unlock()
	u := strings.TrimRight(c.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	r, e := c.http.Do(req)
	if e != nil {
		return discovery{}, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return discovery{}, fmt.Errorf("OIDC discovery HTTP %d", r.StatusCode)
	}
	var d discovery
	if e = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&d); e != nil {
		return d, e
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return d, fmt.Errorf("incomplete OIDC discovery")
	}
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(c.cfg.Issuer, "/") {
		return d, fmt.Errorf("OIDC issuer mismatch")
	}
	c.mu.Lock()
	c.disc = d
	c.mu.Unlock()
	return d, nil
}
func (c *Client) Begin(ctx context.Context) (string, error) {
	d, e := c.discover(ctx)
	if e != nil {
		return "", e
	}
	state, _ := randString(24)
	verifier, _ := randString(32)
	nonce, _ := randString(24)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{"response_type": {"code"}, "client_id": {c.cfg.ClientID}, "redirect_uri": {c.cfg.RedirectURL}, "scope": {strings.Join(c.cfg.Scopes, " ")}, "state": {state}, "nonce": {nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	c.mu.Lock()
	c.pending[state] = pending{Verifier: verifier, Nonce: nonce, Expires: time.Now().Add(10 * time.Minute)}
	c.mu.Unlock()
	return d.AuthorizationEndpoint + "?" + q.Encode(), nil
}
func (c *Client) Callback(ctx context.Context, state, code string) (Claims, string, error) {
	c.mu.Lock()
	p, ok := c.pending[state]
	delete(c.pending, state)
	c.mu.Unlock()
	if !ok || time.Now().After(p.Expires) {
		return nil, "", fmt.Errorf("invalid or expired OIDC state")
	}
	d, e := c.discover(ctx)
	if e != nil {
		return nil, "", e
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.cfg.RedirectURL}, "client_id": {c.cfg.ClientID}, "code_verifier": {p.Verifier}}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, e := c.http.Do(req)
	if e != nil {
		return nil, "", e
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return nil, "", fmt.Errorf("OIDC token HTTP %d", r.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if e = json.Unmarshal(b, &tr); e != nil || tr.IDToken == "" {
		return nil, "", fmt.Errorf("OIDC id_token missing")
	}
	claims, e := c.verifyIDToken(ctx, d, tr.IDToken, p.Nonce)
	if e != nil {
		return nil, "", e
	}
	username := claimString(claims, c.cfg.UsernameClaim)
	if username == "" {
		username = claimString(claims, "email")
	}
	if username == "" {
		username = claimString(claims, "sub")
	}
	if username == "" {
		return nil, "", fmt.Errorf("OIDC identity has no usable username")
	}
	return claims, username, nil
}
func (c *Client) verifyIDToken(ctx context.Context, d discovery, tok, nonce string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}
	hb, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return nil, e
	}
	pb, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return nil, e
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return nil, e
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &h) != nil || h.Alg != "RS256" {
		return nil, fmt.Errorf("OIDC requires RS256 in this build")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
	r, e := c.http.Do(req)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	var keys jwks
	if e = json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&keys); e != nil {
		return nil, e
	}
	var key *rsa.PublicKey
	for _, k := range keys.Keys {
		if k.Kid == h.Kid && k.Kty == "RSA" {
			key, e = rsaKey(k)
			if e != nil {
				return nil, e
			}
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("OIDC signing key not found")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if e = rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); e != nil {
		return nil, fmt.Errorf("OIDC signature invalid")
	}
	var cl Claims
	if e = json.Unmarshal(pb, &cl); e != nil {
		return nil, e
	}
	if claimString(cl, "iss") != d.Issuer {
		return nil, fmt.Errorf("OIDC iss mismatch")
	}
	if !audContains(cl["aud"], c.cfg.ClientID) {
		return nil, fmt.Errorf("OIDC aud mismatch")
	}
	if exp, ok := number(cl["exp"]); !ok || time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("OIDC token expired")
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(claimString(cl, "nonce")), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("OIDC nonce mismatch")
	}
	return cl, nil
}
func rsaKey(k jwk) (*rsa.PublicKey, error) {
	nb, e := base64.RawURLEncoding.DecodeString(k.N)
	if e != nil {
		return nil, e
	}
	eb, e := base64.RawURLEncoding.DecodeString(k.E)
	if e != nil {
		return nil, e
	}
	n := new(big.Int).SetBytes(nb)
	ei := 0
	for _, b := range eb {
		ei = ei<<8 + int(b)
	}
	if ei == 0 {
		return nil, fmt.Errorf("bad RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: ei}, nil
}
func claimString(c Claims, k string) string {
	if v, ok := c[k].(string); ok {
		return v
	}
	return ""
}
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case json.Number:
		f, e := x.Float64()
		return f, e == nil
	}
	return 0, false
}
func audContains(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return x == want
	case []any:
		for _, v := range x {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (c *Client) DefaultRole() string { return c.cfg.DefaultRole }
