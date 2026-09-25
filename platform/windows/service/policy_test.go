package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{}
	for _, name := range requiredRuntimeFiles {
		body := []byte("fixture:" + name)
		if err := os.WriteFile(filepath.Join(root, name), body, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		files[name] = hex.EncodeToString(digest[:])
	}
	raw, _ := json.Marshal(manifest{Schema: 1, Files: files})
	if err := os.WriteFile(filepath.Join(root, "runtime-manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestManifestAcceptsOnlyExactUntamperedRuntime(t *testing.T) {
	root := writeFixture(t)
	if err := validateManifest(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "goodbyedpi.exe"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateManifest(root); err == nil {
		t.Fatal("tampered executable was accepted")
	}
}

func TestManifestRejectsAdditionalFileDeclaration(t *testing.T) {
	root := writeFixture(t)
	raw, _ := os.ReadFile(filepath.Join(root, "runtime-manifest.json"))
	var document manifest
	_ = json.Unmarshal(raw, &document)
	document.Files["cmd.exe"] = document.Files["goodbyedpi.exe"]
	raw, _ = json.Marshal(document)
	_ = os.WriteFile(filepath.Join(root, "runtime-manifest.json"), raw, 0600)
	if err := validateManifest(root); err == nil {
		t.Fatal("broadened runtime manifest was accepted")
	}
}
