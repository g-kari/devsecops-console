# Trial artifact verification

This is a short-lived, unsigned trial build, not a stable GitHub Release. No tag
is created. The stable auto-updater does not distribute these artifacts.

Use only a `trial-<full source SHA>-<OS>-<arch>-<run>-<attempt>` artifact from a
successful **post-merge main push** run of **Trial artifacts**. Candidate artifacts
and pull-request runs are not approved downloads. Artifacts expire after 7 days.

The binary and module keep the compatible name `dependabot-alert-notice`.
`trial-manifest.json` records its exact version, full source/tree SHA, workflow/run,
target, checksum, and verification limits. The version must equal
`0.0.0-trial.g<full source SHA>`. SHA-256 checks provide integrity, not signing.

The manifest keeps `build_run_attempt` and `candidate_artifact` from the producer
build, separately from the ready artifact's `verification_run_attempt`. Retrying
only failed jobs reuses the successful build's original candidate, not a name
derived from the new attempt. Native jobs may also be reused; their exact attempts
are recorded in the linked run's job history. Candidate retention is 1 day. If it
has expired, rerun the whole workflow to rebuild rather than retry failed jobs.

## Extract and check

Download the artifact for your OS/CPU and extract GitHub's outer ZIP into a **new
folder**, not an existing app installation. On Mac/Linux, run `sha256sum -c
SHA256SUMS` (Mac: `shasum -a 256 -c SHA256SUMS`) there. On Windows, compare
`Get-FileHash <filename> -Algorithm SHA256` with the matching SHA256SUMS entries.
Check every file, including the launchers and trial config, before running them.

Extract the single `dependabot-alert-notice_...tar.gz` in that same new folder.
The binary must sit beside Trial.sh / Trial.ps1 and trial-config.yaml. Do not
follow the stable installation instructions in the binary archive's README.
Do not run the binary directly, normal Mac Start/Setup/Update commands, or service
installation. No normal Mac convenience ZIP is included in the ready artifact.

Mac/Linux, using Bash:

```bash
bash Trial.sh
bash Trial.sh --web-url
```

Windows, from PowerShell (no execution-policy changes required or requested):

```powershell
.\Trial.ps1
.\Trial.ps1 -Mode WebURL
```

If the OS, PowerShell policy, or corporate policy blocks the unsigned file, stop
and report the restriction. Do not remove quarantine or bypass security policy.

The first command must print `dependabot-alert-notice` followed by the exact
manifest version. The second must print `http://127.0.0.1:18999`. Each invocation
uses a fresh temporary directory and private HOME/config paths, clears the child
environment, disables auto-update, and checks that the smoke created no DB.
The Unix launcher resolves that new directory to its physical path so aliases
such as macOS `/var` and `/private/var` use the same HOME, cwd and config identity.
GitHub/AI/Slack/Discord credentials and normal app config are not inherited.

## Optional empty/offline UI trial

After the above checks, explicitly start an empty instance with `bash Trial.sh
--start` or `.\Trial.ps1 -Mode Start`. This creates a new disposable trial DB.
The terminal prints its new data directory. No existing config or DB is opened.
Open `http://127.0.0.1:18999/settings` yourself only after the app reports that it
is listening. If port 18999 is already occupied or startup reports an error, stop
and report it; do not mistake an existing service for this trial.

The fixed trial config uses no monitored repositories, RSS/threat fetching,
automatic AI evaluation, notifications, or approvals. External CLI paths point
to missing files and PATH points to the fresh empty directory. Do not enter
credentials, change integration settings, install a service, or import production
data during this trial. This is safe startup configuration, not an OS network
sandbox. Live integrations and normal installation need a separate verification.

Stop with Ctrl+C. The fresh trial directory is retained for your inspection;
normal data and services are untouched. Every launch starts fresh.

## What CI does and does not verify

- Linux amd64: full Go format/vet/build/race tests and native delivered-binary
  version/web-URL smoke through the isolated trial launcher.
- macOS arm64 (Apple Silicon): full native Go race tests, packaging helper regressions,
  trial-launcher version/web-URL smoke; the existing Mac ZIP/launcher/checksum
  gate is also checked but that ZIP is not distributed here.
- Windows amd64 (Windows PowerShell 5.1): vet/build, native updater regression tests, checksum and native
  delivered-binary version/web-URL smoke through the isolated trial launcher.
- macOS amd64 (Intel) / Linux arm64 / Windows arm64: cross-compiled and
  checksummed only; no native run. Intel Mac is intentionally excluded from
  the Trial and Release native CI matrices. Its archive remains available,
  but native binary smoke and full native race tests are not verified.

The six target archives, two Mac convenience ZIP builds and six main-push ready
artifacts are retained. For Intel Mac, the ready manifest reports
`native_binary_smoke: false`, `full_native_race_tests: false`, and
`smoke_scope: not run; cross-compiled only`. This policy change does not resolve
prior Intel test timeouts or establish Intel runtime compatibility.

CI does **not** establish interactive UI behavior, live integrations, Apple
container/Podman isolation, M4 hardware behavior, launchd/service installation,
restart behavior, Developer ID signing/notarization, or user-device verification.
Record OS/CPU, manifest source/version/run, and observed pass/fail/not-run results.
Never include real credentials or production data in the report.
