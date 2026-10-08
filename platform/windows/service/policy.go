package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

var requiredRuntimeFiles = []string{
	"WinDivert.dll",
	"WinDivert64.sys",
	"discord-hosts.txt",
	"gateway-windows.json",
	"go-pcap2socks.exe",
	"goodbyedpi.exe",
}

type manifest struct {
	Schema       int               `json:"schema"`
	HealthSchema int               `json:"health_schema"`
	Files        map[string]string `json:"files"`
}

func validateManifest(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, "runtime-manifest.json"))
	if err != nil {
		return fmt.Errorf("read runtime manifest: %w", err)
	}
	var document manifest
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("parse runtime manifest: %w", err)
	}
	if document.Schema != 1 || document.HealthSchema != 1 || len(document.Files) != len(requiredRuntimeFiles) {
		return fmt.Errorf("runtime manifest has an unsupported schema or file set")
	}
	names := make([]string, 0, len(document.Files))
	for name := range document.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for index, expected := range requiredRuntimeFiles {
		if names[index] != expected {
			return fmt.Errorf("runtime manifest contains unexpected file %q", names[index])
		}
		want := document.Files[expected]
		if len(want) != 64 {
			return fmt.Errorf("invalid SHA-256 for %s", expected)
		}
		path := filepath.Join(root, expected)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("runtime file is absent or unsafe: %s", expected)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", expected, err)
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, io.LimitReader(file, 64*1024*1024+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("hash %s", expected)
		}
		got := hex.EncodeToString(digest.Sum(nil))
		if got != want {
			return fmt.Errorf("SHA-256 mismatch for %s", expected)
		}
	}
	return nil
}
