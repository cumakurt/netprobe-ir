package config

import "testing"

func TestRemoteBindRequiresAuth(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.Listen = "0.0.0.0:8443"
	c.Auth.Enabled = false
	if e := c.Prepare(); e == nil {
		t.Fatal("expected remote auth rejection")
	}
	c.AuthToken = "secret"
	if e := c.Prepare(); e != nil {
		t.Fatal(e)
	}
}

func TestSecurityAndOIDCValidation(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.Security.ConsoleAllowedCIDRs = []string{"not-a-cidr"}
	if e := c.Prepare(); e == nil {
		t.Fatal("expected CIDR validation error")
	}
	c = Default()
	c.DataDir = t.TempDir()
	c.OIDC.Enabled = true
	if e := c.Prepare(); e == nil {
		t.Fatal("expected OIDC required fields error")
	}
	c.OIDC.Issuer = "https://id.example"
	c.OIDC.ClientID = "netprobe"
	c.OIDC.RedirectURL = "https://netprobe.example/api/v1/auth/oidc/callback"
	if e := c.Prepare(); e != nil {
		t.Fatal(e)
	}
}

func TestSignedConfigRequiresPinnedKey(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.Security.RequireSignedConfig = true
	if e := c.Prepare(); e == nil {
		t.Fatal("expected trusted key validation")
	}
}

func TestProfilesEndpointValidation(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.Profiles.Enabled = true
	c.Profiles.Endpoint = "file:///tmp/profile"
	if err := c.Prepare(); err == nil {
		t.Fatal("expected profiles endpoint validation error")
	}
	c.Profiles.Endpoint = "https://otel.example/v1development/profiles"
	if err := c.Prepare(); err != nil {
		t.Fatal(err)
	}
}
