# DeepSecret CLI

`secret` sends and receives end-to-end encrypted secrets from the command line: files, folders, key-value pairs and text.

Everything is encrypted on your machine, with hybrid post-quantum encryption, before it is uploaded. The server stores only ciphertext and never sees a content key. The encryption lives in the [DeepSecret Go SDK](https://github.com/deepsecret-io/deepsecret-go), and [PROTOCOL_V4.md](https://github.com/deepsecret-io/deepsecret-go/blob/main/PROTOCOL_V4.md) specifies it.

You need a [DeepSecret](https://deepsecret.io) account, with a free trial or a plan, to send and receive.

## Install

Each [release](https://github.com/deepsecret-io/cli/releases) has an archive for macOS, Linux and Windows, on arm64 and amd64 (x86_64). For macOS on Apple silicon:

```bash
curl -fsSLO https://github.com/deepsecret-io/cli/releases/latest/download/secret_darwin_arm64.tar.gz
curl -fsSLO https://github.com/deepsecret-io/cli/releases/latest/download/SHA256SUMS
shasum -a 256 --check --ignore-missing SHA256SUMS
tar -xzf secret_darwin_arm64.tar.gz
sudo install -d /usr/local/bin && sudo install -m 755 secret_darwin_arm64/secret /usr/local/bin/secret
```

The other archives are `secret_darwin_amd64` (Intel Macs), `secret_linux_<arch>_fido2` (Linux with glibc, with security key support) and `secret_linux_<arch>` (any Linux, Alpine included, fully static, without security key support), with `amd64` or `arm64` for `<arch>`. On Linux, check with `sha256sum --check --ignore-missing SHA256SUMS`. [Verifying a release](#verifying-a-release) shows how to check the signature and the build provenance too.

On Windows, in PowerShell (use `secret_windows_arm64` on Arm):

```powershell
curl.exe -fsSLO https://github.com/deepsecret-io/cli/releases/latest/download/secret_windows_amd64.zip
curl.exe -fsSLO https://github.com/deepsecret-io/cli/releases/latest/download/SHA256SUMS
$want = (Select-String -Path SHA256SUMS -Pattern ' secret_windows_amd64\.zip$').Line.Split(' ')[0]
if ((Get-FileHash secret_windows_amd64.zip -Algorithm SHA256).Hash -ne $want) { throw 'checksum mismatch' }
Expand-Archive secret_windows_amd64.zip -DestinationPath .
```

Then move `secret_windows_amd64\secret.exe` to a folder on your `PATH`. The Windows build has no security key support.

### From source

You need Go 1.26 or newer.

```bash
git clone https://github.com/deepsecret-io/cli.git
cd cli
go build -trimpath -o secret ./cmd/secret
```

Then move `secret` somewhere on your `PATH`. `secret --version` says `dev` on a build like this one.

It builds on macOS, Linux and Windows.

## Quick start

```bash
# Sign in through your browser (Google)
secret login

# Make a key pair and register its public keys. Add --password to encrypt the private keys with a password.
secret identity generate --sync

# Check the setup
secret doctor

# Send a file. With no recipient, it is sent to you.
secret encrypt db.env -t alice@example.com

# See what was sent to you, then open it
secret list
secret decrypt <secret-id>
```

Files are written to a folder named after the revision, `./<revision-id>/`, so a decrypt never writes over files in the current folder. A message or key-value data is printed to stdout.

## Commands

| Command | What it does |
|---|---|
| `secret login`, `logout` | Sign in through the browser, or revoke and remove the stored login |
| `secret whoami` | Show the account you are signed in as |
| `secret doctor` | Check your login, plan, keys and configuration |
| `secret encrypt` | Encrypt data on this machine and upload it as a secret |
| `secret decrypt` | Download and decrypt a secret |
| `secret list` | List your inbox, or with `--sent` what you sent |
| `secret describe` | Show a secret's details |
| `secret policy` | Change a secret's expiry or IP lock |
| `secret revoke` | Remove recipients of a secret you sent |
| `secret delete` | Delete secrets you sent |
| `secret resume` | Finish or discard an interrupted upload, or list interrupted transfers |
| `secret identity` | Manage your key pairs and the keys you know |
| `secret groups` | List and inspect the groups you can send to: every group for owners and admins, your own for members |
| `secret config` | Show the settings, or save an API key |
| `secret completion` | Generate a shell completion script |

`secret <command> --help` lists every option, with examples.

### Sending

```bash
# Several files and a folder, to two people
secret encrypt auth.service traefik/ -t alice@example.com,bob@example.com

# Key-value pairs
secret encrypt -d DB_PASS=secret -d API_KEY=abc -t alice@example.com

# Every other member of a group
secret encrypt db.env -g engineering

# Expire after a day, and allow one network only
secret encrypt key.pem -t alice@example.com --ttl 24h --ip 10.0.0.0/8

# Hide file names and sizes from the server
secret encrypt . --archive -t alice@example.com

# Write an encrypted file and upload nothing
secret encrypt db.env -t alice@example.com --local
```

You are a recipient only when you list yourself, or when you list nobody. Sending again under an existing name adds a revision, and must list everyone who has access now, or add `--revoke-missing`.

### Receiving

```bash
secret decrypt 3f2a9c1e-... --dir ./out         # choose the folder
secret decrypt 3f2a9c1e-... -o db.env           # a message or data, to a file
secret decrypt 3f2a9c1e-... -r 7b1d...          # a specific revision
secret decrypt --local db.env.cbor              # a file from encrypt --local
```

Large transfers stream from disk and resume. `--progress` shows each connection as it goes. Run the same decrypt again to continue a download, and `secret resume` to finish an upload.

### Revoking

```bash
secret revoke 3f2a9c1e-... --to bob@example.com
```

This stops a recipient downloading any revision. They keep whatever they already downloaded.

### Whose key is this?

The server lists everyone's public keys, so the CLI remembers the key it first used for each person, and refuses a send to them, or a secret from them, under any other key until you accept it. When someone's key changes, confirm the new one with them over a channel you trust, then accept its full 64-character fingerprint:

```bash
secret identity accept alice@example.com <fingerprint>
```

`secret identity verify alice@example.com` shows the key to compare with them, and with the fingerprint added it marks that key verified. They see theirs with `secret identity show`. `secret identity known` lists the keys this device has accepted.

## Configuration

The CLI keeps its login, keys and settings in `~/.deepsecret` (`%USERPROFILE%\.deepsecret` on Windows), private to your user: mode 0700 and 0600 on macOS and Linux, and on Windows an ACL that grants your account alone. Decrypted files get the same protection. On Windows the CLI refuses a config, login or key file that another account may open, and says which `icacls` command fixes it.

| Variable | What it does |
|---|---|
| `DS_API_KEY` | The API key to use, for CI and scripts |
| `DS_LOG` | Log to stderr at this level: `trace`, `debug`, `info`, `warn` or `error`, or `json` for JSON logs |
| `DS_LOG_PATH` | Write logs to this file instead of stderr |
| `DEEPSECRET_TMPDIR` | Where temporary files and the encrypted copies of transfers go. It must be private to your user |
| `NO_COLOR` | Turn off colors |

`--debug` writes debug logs to stderr, with each transfer's plan.

### API keys

For CI and scripts, create a key in the app at <https://app.deepsecret.io/account/api-keys>. Prefer `DS_API_KEY`, `--api-key-file` or `--api-key-stdin`: a key given with `--api-key` shows in process listings.

```bash
secret list --api-key-file ./key.txt

# Or save it for later commands
secret config --save-api-key --api-key-stdin < key.txt
```

A key given with a flag or `DS_API_KEY` comes before your login. A saved key is used when you are not logged in.

### The API address

The address of the API is compiled in. No flag, variable or config file changes it, so a tampered config cannot send your traffic elsewhere. To use another deployment, change the `APIBaseURL` constant and build your own binary.

## Verifying a release

GitHub Actions builds every release from its `vX.Y.Z` tag. Next to the archives, each release has `SHA256SUMS`, its Sigstore signature `SHA256SUMS.sigstore.json` and an SBOM per archive, and every file has a GitHub build provenance attestation. The checksum alone catches a damaged download; the signature and the attestation show that this repository's Release workflow made the file:

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/deepsecret-io/cli/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify secret_darwin_arm64.tar.gz --repo deepsecret-io/cli \
  --signer-workflow deepsecret-io/cli/.github/workflows/release.yml
```

Use the tag you downloaded in the certificate identity. [RELEASING.md](RELEASING.md) explains each check, how to rebuild a release byte for byte, and how releases are made.

## Development

```bash
go vet ./...
go test -race ./...
task security   # known vulnerabilities, gosec, licenses, and secrets in git history
```

`task` is [Task](https://taskfile.dev). `task --list` shows the rest.

To work on the CLI and the SDK together, put a `go.work` that points the SDK at your checkout next to `go.mod`. It is ignored by git, and releases never use it.

### Layout

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

## Security

Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) explains.

## License

[Apache-2.0](LICENSE)
