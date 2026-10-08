package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHealthFailureThresholdAndRecovery(t *testing.T) {
	var p healthPolicy
	for i := 0; i < 2; i++ {
		if _, restart := p.observe(healthResult{}, errors.New("timeout")); restart {
			t.Fatal("premature restart")
		}
	}
	if msg, restart := p.observe(healthResult{LocalOK: true}, nil); restart || !strings.Contains(msg, "internet") {
		t.Fatal("external outage triggered restart")
	}
	for i := 0; i < 3; i++ {
		_, restart := p.observe(healthResult{Reason: "capture unavailable"}, nil)
		if restart != (i == 2) {
			t.Fatalf("local failure %d restart %v", i, restart)
		}
	}
	if msg, restart := p.observe(healthResult{LocalOK: true, InternetOK: true}, nil); restart || !strings.Contains(msg, "Discord") {
		t.Fatal("Discord outage triggered restart")
	}
	if msg, restart := p.observe(healthResult{LocalOK: true, InternetOK: true, DiscordOK: true}, nil); msg != "" || restart {
		t.Fatal("healthy state not restored")
	}
}

func TestProbeRejectsWrongIdentityAndOversize(t *testing.T) {
	for _, body := range []string{`{"schema":1,"pid":99,"local_ok":true}`, `{"schema":2,"pid":42}`, strings.Repeat("x", 4097), `{"schema":1,"pid":42} {}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		_, err := probeHealth(context.Background(), server.Client(), strings.TrimPrefix(server.URL, "http://"), "token", 42)
		server.Close()
		if err == nil {
			t.Fatal("unsafe response accepted")
		}
	}
}

func TestProbeAuthenticationAndCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing per-run authentication")
		}
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := probeHealth(ctx, server.Client(), strings.TrimPrefix(server.URL, "http://"), "secret", 42)
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("probe blocked stop")
	}
}

func TestProbeValidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"schema":1,"pid":42,"local_ok":true,"internet_ok":true,"discord_ok":true}`)
	}))
	defer server.Close()
	h, err := probeHealth(context.Background(), server.Client(), strings.TrimPrefix(server.URL, "http://"), "token", 42)
	if err != nil || !h.LocalOK || !h.DiscordOK || !h.InternetOK {
		t.Fatal(h, err)
	}
}

func TestTailBoundedUnderConcurrentOutput(t *testing.T) {
	tail := &tailWriter{}
	var writers sync.WaitGroup
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 100; j++ {
				_, _ = tail.Write([]byte(strings.Repeat("x", 8192)))
			}
		}()
	}
	writers.Wait()
	_, _ = tail.Write([]byte("last failure"))
	if s := tail.String(); len(s) > tailLimit || !strings.HasSuffix(s, "last failure") {
		t.Fatal("tail overflow or lost last error")
	}
}

func TestPipeFloodDoesNotBlockChild(t *testing.T) {
	if os.Getenv("KONSOLLINK_OUTPUT_FIXTURE") == "1" {
		for i := 0; i < 128; i++ {
			_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 8192)))
			_, _ = os.Stderr.Write([]byte(strings.Repeat("y", 8192)))
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPipeFloodDoesNotBlockChild$")
	cmd.Env = append(os.Environ(), "KONSOLLINK_OUTPUT_FIXTURE=1")
	tail := &tailWriter{}
	cmd.Stdout = tail
	cmd.Stderr = tail
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if len(tail.String()) != tailLimit {
		t.Fatal("unbounded or missing output")
	}
}

func TestDiagnosticsRotateAndReplaceAcrossRestart(t *testing.T) {
	root := t.TempDir()
	d := newDiagnostics(root)
	for i := 0; i < 200; i++ {
		if err := d.write("degraded", strings.Repeat("a", 2048)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"events.jsonl", "events.jsonl.1"} {
		info, err := os.Stat(filepath.Join(root, "diagnostics", name))
		if err != nil || info.Size() > logLimit {
			t.Fatal(name, info, err)
		}
	}
	d = newDiagnostics(root)
	if err := d.write("healthy", ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "diagnostics/status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state diagnosticState
	if err = json.Unmarshal(raw, &state); err != nil || state.State != "healthy" || state.Error != "" || state.PID != os.Getpid() || state.CheckedUnix == 0 {
		t.Fatal(state, err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, "diagnostics", "*.tmp"))
	if len(leftovers) != 0 {
		t.Fatal("temporary files leaked")
	}
}

func TestErrorSummaryOmitsNormalTrafficAndRedactsAddresses(t *testing.T) {
	tail := &tailWriter{}
	_, _ = tail.Write([]byte("level=INFO Device 172.24.2.10 joined\nlevel=ERROR write failed on 192.168.1.4 aa:bb:cc:dd:ee:ff\n"))
	msg := errorSummary("gateway", errors.New("exit 1"), tail)
	if strings.Contains(msg, "joined") || strings.Contains(msg, "192.168") || strings.Contains(msg, "aa:bb:") || !strings.Contains(msg, "write failed") {
		t.Fatal(msg)
	}
}

func TestManifestRequiresHealthCapableGateway(t *testing.T) {
	root := writeFixture(t)
	path := filepath.Join(root, "runtime-manifest.json")
	raw, _ := os.ReadFile(path)
	var m manifest
	_ = json.Unmarshal(raw, &m)
	m.HealthSchema = 0
	raw, _ = json.Marshal(m)
	_ = os.WriteFile(path, raw, 0600)
	if validateManifest(root) == nil {
		t.Fatal("legacy runtime accepted")
	}
}
