package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const healthInterval = 45 * time.Second
const tailLimit = 8 * 1024
const logLimit = 64 * 1024

// Writers, including os/exec's pipe drainers, never wait on disk or probes.
type tailWriter struct {
	mu   sync.Mutex
	data []byte
}

func (t *tailWriter) Write(p []byte) (int, error) {
	n := len(p)
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(p) >= tailLimit {
		t.data = append(t.data[:0], p[len(p)-tailLimit:]...)
	} else {
		overflow := len(t.data) + len(p) - tailLimit
		if overflow > 0 {
			t.data = append(t.data[:0], t.data[overflow:]...)
		}
		t.data = append(t.data, p...)
	}
	return n, nil
}
func (t *tailWriter) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.ToValidUTF8(string(t.data), "?")
}

type healthResult struct {
	Schema     int    `json:"schema"`
	PID        int    `json:"pid"`
	LocalOK    bool   `json:"local_ok"`
	DiscordOK  bool   `json:"discord_ok"`
	InternetOK bool   `json:"internet_ok"`
	Reason     string `json:"reason"`
}

type healthPolicy struct{ failures int }

func (p *healthPolicy) observe(h healthResult, err error) (string, bool) {
	if err != nil || !h.LocalOK {
		p.failures++
		reason := "gateway health endpoint unavailable"
		if err == nil {
			reason = h.Reason
		}
		if reason == "" {
			reason = "capture unavailable"
		}
		return fmt.Sprintf("Windows ağ kontrolü: yerel motor doğrulanamadı (%d/3): %s", p.failures, reason), p.failures >= 3
	}
	p.failures = 0
	if !h.InternetOK {
		return "Windows ağ kontrolü: internet erişimi doğrulanamadı; hizmet açık, otomatik yeniden başlatılmayacak.", false
	}
	if !h.DiscordOK {
		return "Windows ağ kontrolü: Discord erişimi doğrulanamadı; hizmet açık, otomatik yeniden başlatılmayacak.", false
	}
	return "", false
}

func probeHealth(ctx context.Context, client *http.Client, addr, token string, pid int) (healthResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var h healthResult
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	if err != nil {
		return h, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(req)
	if err != nil {
		return h, errors.New("health request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return h, fmt.Errorf("health response status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 {
		return h, errors.New("invalid health response size")
	}
	if err = json.Unmarshal(body, &h); err != nil || h.Schema != 1 || h.PID != pid {
		return h, errors.New("invalid health response identity")
	}
	if len(h.Reason) > 256 {
		return h, errors.New("invalid health reason")
	}
	return h, nil
}

type diagnosticState struct {
	Schema      int       `json:"schema"`
	PID         int       `json:"pid"`
	CheckedAt   time.Time `json:"checked_at"`
	CheckedUnix int64     `json:"checked_unix"`
	State       string    `json:"state"`
	Error       string    `json:"error"`
}

type diagnostics struct {
	root      string
	mu        sync.Mutex
	lastState string
}

func newDiagnostics(root string) *diagnostics {
	return &diagnostics{root: filepath.Join(root, "diagnostics")}
}
func (d *diagnostics) write(state, message string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(d.root, 0755); err != nil {
		return err
	}
	message = strings.ToValidUTF8(message, "?")
	if len(message) > 2048 {
		message = message[:2048]
	}
	item := diagnosticState{Schema: 1, PID: os.Getpid(), CheckedAt: time.Now().UTC(), CheckedUnix: time.Now().Unix(), State: state, Error: message}
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(d.root, "status-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err = temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = replaceFile(name, filepath.Join(d.root, "status.json")); err != nil {
		return err
	}
	// Only transitions/errors, not each successful periodic check. Two bounded
	// files retain the last operational events across SCM restarts.
	previous := d.lastState
	d.lastState = state
	if message == "" && state == "healthy" && previous == "healthy" {
		return nil
	}
	path := filepath.Join(d.root, "events.jsonl")
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(raw)+1) > logLimit {
		if err = replaceFile(path, path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Raw output stays in RAM. Persist error lines only, with common address forms
// removed: normal gateway "device joined"/DNS/traffic messages are excluded.
func errorSummary(image string, err error, tails ...*tailWriter) string {
	message := image + " exited"
	if err != nil {
		message += ": " + err.Error()
	}
	for _, tail := range tails {
		for _, line := range strings.Split(tail.String(), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "error") || strings.Contains(lower, "failed") {
				message += "\n" + line
			}
		}
	}
	message = addressPattern.ReplaceAllString(message, "[address]")
	if len(message) > 2048 {
		message = message[:2048]
	}
	return message
}

var addressPattern = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)
