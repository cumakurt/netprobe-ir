package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOIDCFlowRS256(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var issuer string
	var nonce string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "k1", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			_ = r.ParseForm()
			tok := signJWT(key, map[string]any{"alg": "RS256", "kid": "k1"}, map[string]any{"iss": issuer, "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "nonce": nonce, "preferred_username": "alice"})
			json.NewEncoder(w).Encode(map[string]string{"id_token": tok})
		}
	}))
	defer s.Close()
	issuer = s.URL
	c := New(Config{Enabled: true, Issuer: issuer, ClientID: "client", RedirectURL: "http://local/cb"})
	u, e := c.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	q, _ := url.Parse(u)
	state := q.Query().Get("state")
	c.mu.Lock()
	nonce = c.pending[state].Nonce
	c.mu.Unlock()
	_, user, e := c.Callback(context.Background(), state, "code")
	if e != nil || user != "alice" {
		t.Fatalf("%s %v", user, e)
	}
}
func signJWT(k *rsa.PrivateKey, h, p map[string]any) string {
	hb, _ := json.Marshal(h)
	pb, _ := json.Marshal(p)
	a := base64.RawURLEncoding.EncodeToString(hb)
	b := base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(a + "." + b))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	return strings.Join([]string{a, b, base64.RawURLEncoding.EncodeToString(sig)}, ".")
}

var _ = fmt.Sprintf
