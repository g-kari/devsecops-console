// Command package-macos builds standalone Mac distributions using the current
// source tree. Only explicitly listed, non-secret assets are included.
package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"debug/macho"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var assets = []struct {
	source, name string
	mode         fs.FileMode
}{
	{"packaging/macos/Start.command", "Start.command", 0755},
	{"packaging/macos/config.yaml.example", "config.yaml.example", 0644},
	{"packaging/macos/MAC-START.md", "MAC-START.md", 0644},
	{"Dockerfile.codex-evaluator", "Dockerfile.codex-evaluator", 0644},
	{"Dockerfile.evaluator", "Dockerfile.evaluator", 0644},
	{"LICENSE", "LICENSE", 0644},
	{"Dockerfile.apple-claude", "Dockerfile.apple-claude", 0644},
	{"Dockerfile.apple-codex", "Dockerfile.apple-codex", 0644},
	{"scripts/setup-macos.sh", "Setup.command", 0755},
	{"packaging/macos/Update.command", "Update.command", 0755},
	{"packaging/macos/Service.command", "Service.command", 0755},
	{"packaging/macos/Build.command", "Build.command", 0755},
	{"packaging/macos/service-macos.sh", "service-macos.sh", 0755},
	{"packaging/macos/MAC-VERIFY.md", "MAC-VERIFY.md", 0644},
}

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func main() {
	version := flag.String("version", "dev", "配布バージョン")
	out := flag.String("out", "dist", "新しい出力ディレクトリ")
	root := flag.String("root", ".", "リポジトリroot")
	allowDirty := flag.Bool("allow-dirty", false, "未コミットのローカルpreviewを明示的に許可")
	flag.Parse()
	if err := build(context.Background(), *root, *out, *version, *allowDirty); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(ctx context.Context, root, out, version string, allowDirty bool) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("配布バージョンが不正です")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("リポジトリパス取得: %w", err)
	}
	commitCmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	commitCmd.Dir = root
	commit, err := commitCmd.Output()
	if err != nil {
		return fmt.Errorf("配布ソースcommit確認: %w", err)
	}
	statusCmd := exec.CommandContext(ctx, "git", "status", "--porcelain", "--untracked-files=normal")
	statusCmd.Dir = root
	status, err := statusCmd.Output()
	if err != nil {
		return fmt.Errorf("配布ソース状態確認: %w", err)
	}
	dirty := len(status) != 0
	if dirty && !allowDirty {
		return fmt.Errorf("未コミット変更があります。ローカルpreviewは-allow-dirtyを明示してください")
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return fmt.Errorf("配布先作成: %w", err)
	}
	work, err := os.MkdirTemp("", "security-notice-release-*")
	if err != nil {
		return fmt.Errorf("ビルド作業フォルダ作成: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			fmt.Fprintf(os.Stderr, "ビルド作業フォルダ削除: %v\n", err)
		}
	}()
	var checksums strings.Builder
	for _, arch := range []string{"arm64", "amd64"} {
		binary := filepath.Join(work, "dependabot-alert-notice-"+arch)
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X main.version="+version, "-o", binary, ".")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("mac %sビルド: %w", arch, err)
		}
		name := "security-notice_" + version + "_macos_" + arch + ".zip"
		path := filepath.Join(out, name)
		info := fmt.Sprintf("Version: %s\nOS: darwin\nCPU: %s\nSource commit: %s\nUncommitted changes: %t\nApple Developer ID/notarization: not configured\n", version, arch, strings.TrimSpace(string(commit)), dirty)
		if err := writeArchive(root, binary, path, version, arch, info); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("チェックサム入力: %w", err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("チェックサム算出: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("チェックサム入力close: %w", closeErr)
		}
		fmt.Fprintf(&checksums, "%x  %s\n", hash.Sum(nil), name)
		fmt.Println(path)
	}
	file, err := os.OpenFile(filepath.Join(out, "macos-checksums.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("チェックサム作成（既存ファイルは上書きしません）: %w", err)
	}
	_, writeErr := io.WriteString(file, checksums.String())
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("チェックサム保存: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("チェックサムclose: %w", closeErr)
	}
	return nil
}

func writeArchive(root, binary, out, version, arch, buildInfo string) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("配布バージョンが不正です")
	}
	f, err := macho.Open(binary)
	if err != nil {
		return fmt.Errorf("macバイナリ形式確認: %w", err)
	}
	cpu, kind := f.Cpu, f.Type
	if err := f.Close(); err != nil {
		return fmt.Errorf("macバイナリclose: %w", err)
	}
	if kind != macho.TypeExec || (arch != "arm64" || cpu != macho.CpuArm64) && (arch != "amd64" || cpu != macho.CpuAmd64) {
		return fmt.Errorf("Mac対象CPUとバイナリが一致しません: arch=%s cpu=%s type=%s", arch, cpu, kind)
	}
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("配布ZIP作成（既存ファイルは上書きしません）: %w", err)
	}
	z := zip.NewWriter(file)
	prefix := "security-notice_" + version + "_macos_" + arch + "/"
	add := func(source, name string, mode fs.FileMode) error {
		input, err := os.Open(source)
		if err != nil {
			return fmt.Errorf("同梱ファイル取得 %s: %w", name, err)
		}
		defer func() { _ = input.Close() }()
		header := &zip.FileHeader{Name: prefix + name, Method: zip.Deflate}
		header.SetMode(mode)
		writer, err := z.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := io.Copy(writer, input); err != nil {
			return err
		}
		return nil
	}
	packErr := add(binary, "dependabot-alert-notice", 0755)
	for _, asset := range assets {
		if packErr != nil {
			break
		}
		packErr = add(filepath.Join(root, asset.source), asset.name, asset.mode)
	}
	if packErr == nil {
		header := &zip.FileHeader{Name: prefix + "BUILD-INFO.txt", Method: zip.Deflate}
		header.SetMode(0644)
		writer, err := z.CreateHeader(header)
		if err != nil {
			packErr = err
		} else {
			_, packErr = io.WriteString(writer, buildInfo)
		}
	}
	zipErr, closeErr := z.Close(), file.Close()
	if packErr != nil || zipErr != nil || closeErr != nil {
		if err := os.Remove(out); err != nil {
			return fmt.Errorf("失敗した配布ZIP削除: %w", err)
		}
		return fmt.Errorf("配布ZIP保存: content=%v zip=%v close=%v", packErr, zipErr, closeErr)
	}
	return nil
}
