#!/usr/bin/env python3
"""Trial packaging tests; use synthetic environment values and a fake binary."""
import ast
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TRIAL = ROOT / "packaging" / "trial"


class TrialToolsTests(unittest.TestCase):
    def test_native_ci_policy_keeps_arm_mac_and_marks_intel_cross_compiled(self):
        trial = (ROOT / ".github/workflows/trial.yml").read_text()
        release = (ROOT / ".github/workflows/release.yml").read_text()
        for workflow, job in ((trial, "mac-smoke"), (release, "mac-test")):
            section = re.search(r"(?ms)^  " + job + r":\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", workflow).group(1)
            matrix = re.search(r"(?ms)^      matrix:\n(.*?)^    runs-on:", section).group(1)
            self.assertEqual(re.findall(r"runner: (\S+)\n\s+arch: (\S+)", matrix),
                             [("macos-15", "arm64")])
            self.assertNotIn("macos-15-intel", workflow)
            self.assertIn("go test ./... -race -count=1", section)
        ready = re.search(r"(?ms)^  ready:\n(.*)\Z", trial).group(1)
        native = ast.literal_eval(re.search(r"native = \(goos, arch\) in (\{[^\n]+\})", ready).group(1))
        self.assertEqual(native, {("linux", "amd64"), ("windows", "amd64"), ("darwin", "arm64")})
        self.assertIn("os: [linux, darwin, windows]", ready)
        self.assertIn("arch: [amd64, arm64]", ready)
        self.assertIn("'native_binary_smoke': native", ready)
        self.assertIn("'full_native_race_tests': goos in ('linux', 'darwin') and native", ready)
        self.assertIn("else 'not run; cross-compiled only'", ready)
        self.assertIn("'mac-smoke (arm64 only)'", ready)
        self.assertNotIn("mac-smoke (arm64 and amd64)", ready)
        self.assertIn("macOS amd64 (Intel)", (TRIAL / "TRIAL-START.md").read_text())

    def test_failed_job_retries_keep_the_producer_artifact_and_attempt(self):
        workflow = (ROOT / ".github/workflows/trial.yml").read_text()
        reference = "${{ needs.build.outputs.artifact_name }}"
        self.assertIn('echo "artifact_name=candidate-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', workflow)
        self.assertIn('artifact_name: ${{ steps.source.outputs.artifact_name }}', workflow)
        self.assertIn('build_attempt: ${{ steps.source.outputs.build_attempt }}', workflow)
        for job in ("mac-smoke", "windows-smoke", "ready"):
            section = re.search(r"(?ms)^  " + re.escape(job) + r":\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", workflow).group(1)
            self.assertIn("name: " + reference, section)
            self.assertNotIn("name: candidate-", section)
        self.assertIn("'build_run_attempt': os.environ['GITHUB_RUN_ATTEMPT']", workflow)
        self.assertIn("'verification_run_attempt': os.environ['GITHUB_RUN_ATTEMPT']", workflow)
        self.assertIn("manifest['build_run_attempt'] == os.environ['BUILD_RUN_ATTEMPT']", workflow)
        self.assertIn("manifest['candidate_artifact'] == os.environ['CANDIDATE_ARTIFACT']", workflow)
        # Mock GitHub's successful-build outputs surviving failed-jobs retries.
        # No workflow, executable, network, or GitHub mutation is run here.
        for producer_attempt, verification_attempt in ((1, 1), (1, 2), (1, 3), (2, 3)):
            outputs = {"artifact_name": f"candidate-42-{producer_attempt}",
                       "build_attempt": str(producer_attempt)}
            artifact_store = {outputs["artifact_name"]: b"same-immutable-candidate"}
            for job in ("mac-smoke", "windows-smoke", "ready"):
                resolved_name = outputs["artifact_name"]
                self.assertEqual(artifact_store[resolved_name], b"same-immutable-candidate", job)
            manifest = {"build_run_attempt": outputs["build_attempt"],
                        "verification_run_attempt": str(verification_attempt)}
            self.assertEqual(manifest["build_run_attempt"], str(producer_attempt))
            self.assertEqual(manifest["verification_run_attempt"], str(verification_attempt))
            if verification_attempt != producer_attempt:
                self.assertNotIn(f"candidate-42-{verification_attempt}", artifact_store)

    def test_config_is_empty_local_and_offline(self):
        text = (TRIAL / "trial-config.yaml").read_text()
        for line in (
            "targets: []", "  host: 127.0.0.1", "  port: 18999",
            "disable_approval: true", "  auto_eval: false", "  feeds: []",
            "gh_path: ./disabled-gh", "claude_path: ./disabled-claude",
            "codex_path: ./disabled-codex", "    container_path: ./disabled-container",
        ):
            self.assertIn(line, text.splitlines())
        self.assertRegex(text, r"rss:\n  enabled: false\n")
        self.assertRegex(text, r"threat:\n  enabled: false\n")
        self.assertNotIn("https://", text)

    def test_windows_launcher_has_an_allowlisted_child_environment(self):
        text = (TRIAL / "Trial.ps1").read_text()
        self.assertIn("$info.EnvironmentVariables.Clear()", text)
        self.assertIn("$info.UseShellExecute = $false", text)
        self.assertIn("$info.WorkingDirectory = $trial", text)
        self.assertIn("[Guid]::NewGuid()", text)
        self.assertIn("--auto-update=false", text)
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_WEBHOOK_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            self.assertNotIn("EnvironmentVariables['" + name + "']", text)
        self.assertNotIn("ExecutionPolicy", text)

    @unittest.skipIf(os.name == "nt", "Unix launcher needs Bash")
    def test_unix_launcher_clears_credentials_and_separates_home_and_data(self):
        with tempfile.TemporaryDirectory(prefix="trial-tools-") as raw:
            root = pathlib.Path(raw)
            package = root / "package with spaces"
            package.mkdir()
            for item in TRIAL.iterdir():
                shutil.copyfile(item, package / item.name)
            binary = package / "dependabot-alert-notice"
            binary.write_text('''#!/bin/bash
set -Eeuo pipefail
trap 'status=$?; printf "fixture assertion failed: status=%s line=%s command=%s\\nPWD=%s\\nHOME=%s\\nconfig=%s\\n" "$status" "$LINENO" "$BASH_COMMAND" "$PWD" "$HOME" "${2:-unset}" >&2; exit "$status"' ERR
test -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}${SLACK_BOT_TOKEN:-}${SLACK_APP_TOKEN:-}${DISCORD_WEBHOOK_URL:-}${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}"
test "$PATH" = "$HOME/bin"
test "$GH_CONFIG_DIR" = "$HOME/gh"
test "$CODEX_HOME" = "$HOME/codex"
test "$SECURITY_NOTICE_AUTO_UPDATE" = 0
test ! -f "$HOME/original-home-marker"
test "$HOME" -ef "$PWD/home"
test "$#" -eq 4
test "$1" = --config
test "$2" -ef "$PWD/config.yaml"
test "$3" = --auto-update=false
printf '%s\\n' "$PWD" > "$HOME/capture"
case "${4:-}" in
  --version) printf 'dependabot-alert-notice fixture\\n' ;;
  --web-url) printf 'http://127.0.0.1:18999\\n' ;;
  *) exit 8 ;;
esac
''')
            binary.chmod(0o755)
            old_home = root / "old home"
            old_home.mkdir()
            (old_home / "original-home-marker").write_text("keep")
            temp = root / "temporary"
            temp.mkdir()
            alias = root / "temporary alias"
            alias.symlink_to(temp, target_is_directory=True)
            environment = dict(os.environ, HOME=str(old_home), TMPDIR=str(temp),
                               GH_TOKEN="synthetic-only", GITHUB_TOKEN="synthetic-only",
                               SLACK_BOT_TOKEN="synthetic-only", SLACK_APP_TOKEN="synthetic-only",
                               DISCORD_WEBHOOK_URL="synthetic-only", OPENAI_API_KEY="synthetic-only",
                               ANTHROPIC_API_KEY="synthetic-only")
            for temp_root in (temp, alias):
                environment["TMPDIR"] = str(temp_root)
                for mode, expected in (([], "dependabot-alert-notice fixture"),
                                       (["--web-url"], "http://127.0.0.1:18999")):
                    result = subprocess.run(["bash", str(package / "Trial.sh"), *mode],
                                            env=environment, text=True, capture_output=True)
                    diagnostic = (f"mode={mode!r} TMPDIR={temp_root} returncode={result.returncode}"
                                  f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
                    self.assertEqual(result.returncode, 0, diagnostic)
                    self.assertEqual(result.stdout.strip(), expected, diagnostic)
            directories = list(temp.glob("devsecops-trial.*"))
            self.assertEqual(len(directories), 4)
            for directory in directories:
                captured = pathlib.Path((directory / "home/capture").read_text().strip())
                self.assertTrue(directory.samefile(captured), f"different trial directories: {directory} / {captured}")
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual((directory / "config.yaml").read_bytes(), (TRIAL / "trial-config.yaml").read_bytes())
                self.assertFalse((directory / "store.db").exists())
            self.assertEqual((old_home / "original-home-marker").read_text(), "keep")
            rejected = subprocess.run(["bash", str(package / "Trial.sh"), "--update"],
                                      env=environment, capture_output=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(len(list(temp.glob("devsecops-trial.*"))), 4)


if __name__ == "__main__":
    unittest.main()
