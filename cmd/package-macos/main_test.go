package main

import (
	"archive/zip"
	"debug/macho"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func macFixture(t *testing.T, arch string) (string, string) {
	t.Helper()
	root := t.TempDir()
	for _, asset := range assets {
		path := filepath.Join(root, asset.source)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, secret := range []string{"config.yaml", "store.db", "auth.json", ".env"} {
		if err := os.WriteFile(filepath.Join(root, secret), []byte("never distribute"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header, macho.Magic64)
	cpu := macho.CpuArm64
	if arch == "amd64" {
		cpu = macho.CpuAmd64
	}
	binary.LittleEndian.PutUint32(header[4:], uint32(cpu))
	binary.LittleEndian.PutUint32(header[12:], uint32(macho.TypeExec))
	file := filepath.Join(root, "fixture-binary")
	if err := os.WriteFile(file, header, 0755); err != nil {
		t.Fatal(err)
	}
	return root, file
}

func TestArchiveContainsOnlyAllowedAssetsAndUnixExecutableModes(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			root, file := macFixture(t, arch)
			out := filepath.Join(t.TempDir(), "release.zip")
			if err := writeArchive(root, file, out, "v1.2.3", arch, "fixture commit"); err != nil {
				t.Fatal(err)
			}
			z, err := zip.OpenReader(out)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = z.Close() }()
			if len(z.File) != len(assets)+2 {
				t.Fatalf("unexpected files: %d", len(z.File))
			}
			for _, entry := range z.File {
				base := filepath.Base(entry.Name)
				if !strings.HasPrefix(entry.Name, "security-notice_v1.2.3_macos_"+arch+"/") || strings.Contains(entry.Name, "..") {
					t.Fatalf("unsafe entry: %s", entry.Name)
				}
				if base == "config.yaml" || base == "store.db" || base == "auth.json" || base == ".env" {
					t.Fatalf("secret included: %s", entry.Name)
				}
				if (strings.HasSuffix(base, ".command") || strings.HasSuffix(base, ".sh") || base == "dependabot-alert-notice") && entry.Mode().Perm() != 0755 {
					t.Fatalf("not executable: %s mode=%s", entry.Name, entry.Mode())
				}
			}
		})
	}
}

func TestArchiveRejectsWrongCpuNonMacBinaryAndUnsafeVersion(t *testing.T) {
	root, file := macFixture(t, "arm64")
	for _, scenario := range []string{"wrong_cpu", "windows_binary", "version"} {
		t.Run(scenario, func(t *testing.T) {
			arch, version, binaryPath := "amd64", "v1.0", file
			if scenario == "windows_binary" {
				binaryPath = filepath.Join(root, "windows.exe")
				if err := os.WriteFile(binaryPath, []byte("MZ-not-Mach-O"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "version" {
				arch, version = "arm64", "../bad"
			}
			out := filepath.Join(t.TempDir(), "release.zip")
			if err := writeArchive(root, binaryPath, out, version, arch, "fixture"); err == nil {
				t.Fatal("unsafe/mislabelled archive accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("invalid archive left output")
			}
		})
	}
}
