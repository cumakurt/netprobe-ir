package otelprofiles

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Sample struct {
	Time       time.Time         `json:"time"`
	Process    string            `json:"process"`
	PID        int               `json:"pid"`
	Stack      []string          `json:"stack"`
	Value      int64             `json:"value"`
	Unit       string            `json:"unit"`
	Attributes map[string]string `json:"attributes,omitempty"`
}
type Envelope struct {
	Resource map[string]string `json:"resource"`
	Signal   string            `json:"signal"`
	Samples  []Sample          `json:"samples"`
}
type Exporter struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

func (e *Exporter) Export(ctx context.Context, x Envelope) error {
	if e.Endpoint == "" {
		return fmt.Errorf("profiles endpoint required")
	}
	if x.Signal == "" {
		x.Signal = "profiles-experimental"
	}
	b, err := json.Marshal(x)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.Token != "" {
		req.Header.Set("Authorization", "Bearer "+e.Token)
	}
	cl := e.Client
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Second}
	}
	res, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		z, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("profiles export %s: %s", res.Status, bytes.TrimSpace(z))
	}
	return nil
}
