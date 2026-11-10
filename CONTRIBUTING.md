# Contributing to the DeepSecret CLI

## Build from source

You need Go 1.26 or newer. It builds on macOS, Linux and Windows.

```bash
git clone https://github.com/deepsecret-io/cli.git
cd cli
go build -trimpath -o secret ./cmd/secret
```

Then move `secret` somewhere on your `PATH`. `secret --version` says `dev` on a build like this one.

## Develop

```bash
go vet ./...
go test -race ./...
task security   # known vulnerabilities, gosec, licenses, and secrets in git history
```

`task` is [Task](https://taskfile.dev); `task --list` shows the rest.

To work on the CLI and the SDK together, put a `go.work` next to `go.mod` that points the SDK at your checkout. Git ignores it, and releases never use it.

The address of the API is compiled in. No flag, variable or config file changes it, so a tampered config cannot send your traffic elsewhere. To use another deployment, change the `APIBaseURL` constant and build your own binary.

## Layout

Encryption, the protocol and the API live in the [SDK](https://github.com/deepsecret-io/deepsecret-go), which is what other programs should build on. The packages here are internal to the CLI, and imports only go down this list:

| Package | What it holds |
|---|---|
| `cmd/secret` | `main`: the version and the exit code |
| `internal/command` | The cobra commands, one file per command tree |
| `internal/identity` | Key pair files, unlocking them, registered keys and safety numbers |
| `internal/login` | The browser sign-in |
| `internal/auth` | Which credential a command uses, and the SDK client that sends it |
| `internal/pending` | Interrupted transfers on disk |
| `internal/config` | `~/.deepsecret`: paths, the config file and the login token |
| `internal/ui` | Steps, progress, results, warnings, errors and value formatting |
| `internal/logging` | The diagnostic log (`--debug`, `DS_LOG`, `DS_LOG_PATH`) |
| `internal/flags` | Validated flag types, argument checks and grouped help |
| `internal/fingerprint` | Checking, matching and grouping key fingerprints |
| `internal/safefile` | Files private to the user (0600 and 0700, an owner-only ACL on Windows), written without following links or leaving a partial file |
| `internal/prompt` | Hidden terminal input |
| `internal/console` | ANSI styles, terminal detection, sanitizing and the live view |
| `internal/errs` | Errors that carry the detail of their Error block |

## Releases

[RELEASING.md](RELEASING.md) explains how releases are made, signed and verified.

## Security

Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) explains, not in a public issue.
