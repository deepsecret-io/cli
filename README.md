# DeepSecret CLI

Send passwords, API keys, config files and whole folders to the people who need them, end-to-end encrypted. `secret` encrypts everything on your computer before it is uploaded, so only the people you send to can open it. Not even DeepSecret can.

You need a [DeepSecret account](https://app.deepsecret.io). Every plan starts with a 7-day free trial, no card needed.

## Install

### macOS and Linux

```bash
curl -fsSL https://github.com/deepsecret-io/cli/releases/latest/download/install.sh | bash -s -- v0.1.0
```

It picks the right build for your computer, checks it against the release's checksums, and installs `secret` in `/usr/local/bin`, asking for your password only if that folder needs it. To install somewhere else, put `INSTALL_DIR=~/.local/bin` before `bash`.

### Windows

In PowerShell:

```powershell
curl.exe -fsSLO https://github.com/deepsecret-io/cli/releases/latest/download/secret_windows_amd64.zip
curl.exe -fsSLO https://github.com/deepsecret-io/cli/releases/latest/download/SHA256SUMS
$want = (Select-String -Path SHA256SUMS -Pattern ' secret_windows_amd64\.zip$').Line.Split(' ')[0]
if ((Get-FileHash secret_windows_amd64.zip -Algorithm SHA256).Hash -ne $want) { throw 'checksum mismatch' }
Expand-Archive secret_windows_amd64.zip -DestinationPath .
```

Then move `secret_windows_amd64\secret.exe` to a folder on your `PATH`. On Windows on Arm, use `secret_windows_arm64` in each line.

### Check it worked

```bash
secret --version
```

Every build is on the [releases page](https://github.com/deepsecret-io/cli/releases). To check a download's signature too, see [Verify a download](RELEASING.md#verify-a-download). To build it yourself, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Get started

Three commands, once per computer:

```bash
secret login               # sign in with your browser
secret identity generate   # create your keys (add --password to protect them with a password)
secret doctor              # check that everything is ready
```

Send a file:

```bash
secret encrypt db.env -t alice@example.com
```

Alice opens it on her computer:

```bash
secret list                  # what was sent to her
secret decrypt <secret-id>   # download and decrypt it
```

Files go to a new folder named after the revision, so nothing in your current folder is ever overwritten. Text and key-value pairs are printed instead.

## Everyday use

| To | Run |
|---|---|
| Send files or a folder to several people | `secret encrypt app.env certs/ -t alice@example.com,bob@example.com` |
| Send key-value pairs | `secret encrypt -d DB_PASS=hunter2 -d API_KEY=abc -t alice@example.com` |
| Send to a group in your organization | `secret encrypt db.env -g engineering` |
| Make it expire, or work from one network only | `secret encrypt key.pem -t alice@example.com --ttl 24h --ip 10.0.0.0/8` |
| Hide file names and sizes from the server | `secret encrypt . --archive -t alice@example.com` |
| See what you sent | `secret list --sent` |
| Open a secret into a folder you choose | `secret decrypt <secret-id> --dir ./out` |
| Take back someone's access | `secret revoke <secret-id> --to bob@example.com` |
| Delete a secret you sent | `secret delete <secret-id>` |
| Finish an interrupted upload | `secret resume` |

Sending again under the same name adds a new revision of that secret. `secret <command> --help` shows every option, with examples, and the [documentation](https://deepsecret.io/docs.html) explains it all in depth.

## When someone's key changes

The CLI remembers the key it first saw for each person. If their key ever changes, it stops sending to them and opening their secrets until you accept the new one. Confirm the new key with them over a channel you trust, like a call, then accept it:

```bash
secret identity verify alice@example.com                  # shows the key to compare with Alice
secret identity accept alice@example.com <fingerprint>    # accept it once she confirms
```

## Scripts and CI

Create an API key in the app under [Account › API keys](https://app.deepsecret.io/account/api-keys), then give it to the CLI in an environment variable or a file:

```bash
DS_API_KEY=... secret list
secret list --api-key-file ./key.txt
```

Avoid `--api-key` on the command line: other users of the computer can see it in the process list.

## Settings

The CLI keeps your login, keys and settings in `~/.deepsecret` (`%USERPROFILE%\.deepsecret` on Windows), readable only by you. It refuses to use a file there that other accounts on the computer can open, and tells you the command that fixes it.

| Variable | What it does |
|---|---|
| `DS_API_KEY` | The API key to use, for CI and scripts |
| `DS_LOG` | Log at this level: `trace`, `debug`, `info`, `warn` or `error`, or `json` |
| `DS_LOG_PATH` | Write the log to this file instead of the terminal |
| `DEEPSECRET_TMPDIR` | Where temporary and in-transit files go (must be private to you) |
| `NO_COLOR` | Turn off colors |

## Security

Everything is encrypted on your computer with hybrid post-quantum encryption and signed by the sender. The encryption lives in the open source [DeepSecret Go SDK](https://github.com/deepsecret-io/deepsecret-go), and [PROTOCOL_V4.md](https://github.com/deepsecret-io/deepsecret-go/blob/main/PROTOCOL_V4.md) specifies it.

To report a vulnerability, please follow [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
