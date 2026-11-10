# DeepSecret CLI

Send passwords, API keys, config files and whole folders to the people who need them, end-to-end encrypted. `secret` encrypts everything on your computer before it is uploaded, for the people you send to. DeepSecret stores only the encrypted data and never has the keys to open it.

You need a [DeepSecret account](https://app.deepsecret.io). Every plan starts with a 7-day free trial, no card needed.

## Install

**macOS and Linux:**

```bash
curl -fsSL https://github.com/deepsecret-io/cli/releases/latest/download/install.sh | bash
```

**Windows**, in PowerShell:

```powershell
irm https://github.com/deepsecret-io/cli/releases/latest/download/install.ps1 | iex
```

Both pick the right build for your computer, check that it downloaded intact against the release's checksums, and install `secret`: in `/usr/local/bin` on macOS and Linux (asking for your password only if that folder needs it), and in `%LOCALAPPDATA%\Programs\DeepSecret` on Windows, added to your `PATH`, with no administrator rights needed. Open a new terminal, then check it worked:

```bash
secret --version
```

<details>
<summary>Other ways to install</summary>

- **A specific version:** `curl -fsSL https://github.com/deepsecret-io/cli/releases/latest/download/install.sh | bash -s -- v0.1.0`, or on Windows set `$env:DEEPSECRET_VERSION = 'v0.1.0'` before the command.
- **Another folder:** put `INSTALL_DIR=~/.local/bin` before `bash`, or set `$env:INSTALL_DIR` on Windows.
- **With the signature checked:** on macOS and Linux, the installer also checks that the release workflow signed the checksums when [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is installed. Otherwise, or by hand, download your platform's archive and `SHA256SUMS` from the [releases page](https://github.com/deepsecret-io/cli/releases) and check them as [Verify a download](RELEASING.md#verify-a-download) shows.
- **From source:** see [CONTRIBUTING.md](CONTRIBUTING.md).

</details>

## Set up, once per computer

**1. Sign in.** It opens your browser:

```bash
secret login
```

**2. Create your keys.** Your private keys never leave this computer. Choose how to protect them:

| Protection | Command | To decrypt, you |
|---|---|---|
| None: the keys are stored unencrypted, readable only by your user account | `secret identity generate` | do nothing |
| A password | `secret identity generate --password` | type the password |
| A security key such as a YubiKey, plus a backup security key | `secret identity generate --security-key --backup` | touch either key |
| A security key, plus a printed recovery code | `secret identity generate --security-key --recovery-code` | touch the key, or type the code if it is lost |
| One security key and nothing else | `secret identity generate --security-key --single` | touch the key. If you lose it, the keys are gone for good |

Security keys work on macOS and on Linux (the installer picks the build with security key support when your Linux has it), not on Windows. You can add one to existing keys later with `secret identity security-key`.

The new keys are registered with your account, so people can send to you. To keep them on this computer only for now, add `--local`, and register them later with `secret identity sync`.

**3. Check that everything is ready:**

```bash
secret doctor
```

## Send a secret

Files, folders, or key-value pairs, to whoever needs them:

```bash
# To yourself: with no recipient, only you can open it (to move it to another computer of yours, say)
secret encrypt db.env

# To someone else: only Alice can open it, not you
secret encrypt db.env -t alice@example.com

# To several people, yourself included
secret encrypt db.env -t alice@example.com,bob@example.com,me@example.com

# To a group in your organization: every other member of the group
secret encrypt db.env -g engineering

# Several files and a folder, under a name of your choice
secret encrypt app.env certs/ -t alice@example.com -n "staging config"

# Key-value pairs instead of files
secret encrypt -d DB_PASS=hunter2 -d API_KEY=abc -t alice@example.com
```

Add rules when you send:

```bash
secret encrypt key.pem -t alice@example.com --ttl 24h            # expires in a day
secret encrypt key.pem -t alice@example.com --ip 10.0.0.0/8      # opens from this network only
secret encrypt . -t alice@example.com --archive                  # hides file names and sizes from the server
```

Sending again under the same name adds a new revision of that secret. List everyone who should keep access, or add `--revoke-missing` to take it from anyone you leave out.

## Open a secret

**1. See what was sent to you:**

```bash
secret list
```

**2. Look at one, if you like:** who sent it, its files and its rules.

```bash
secret describe <secret-id>
```

**3. Download and decrypt it:**

```bash
secret decrypt <secret-id>                  # files go to a new folder, ./<revision-id>/
secret decrypt <secret-id> --dir ./out      # or to a folder you choose
secret decrypt <secret-id> -o db.env        # key-value pairs to a file instead of the screen
```

Decrypting never overwrites files in your current folder. Key-value pairs are printed on the screen unless you give `-o`.

## Manage what you sent

| To | Run |
|---|---|
| See what you sent | `secret list --sent` |
| Change when it expires | `secret policy <secret-id> --ttl 48h` |
| Change or remove the network rule | `secret policy <secret-id> --ip 10.0.0.0/8`, or `--clear-ips` |
| Take back someone's access | `secret revoke <secret-id> --to bob@example.com` |
| Delete it for everyone | `secret delete <secret-id>` |
| Finish an interrupted upload | `secret resume` |

## Watch progress and debug

Every command takes these options:

| Option | What it does |
|---|---|
| `--progress` | Shows a transfer's progress, connection by connection |
| `--debug` | Writes debug logs to the terminal, with each transfer's plan |
| `--help` | Shows every option of a command, with examples |

```bash
secret encrypt backup.tar -t alice@example.com --progress
secret decrypt <secret-id> --progress
secret decrypt <secret-id> --debug
```

For more control, set these before any command:

```bash
DS_LOG=trace secret decrypt <secret-id>                      # level: trace, debug, info, warn or error
DS_LOG=json secret list                                      # logs as JSON
DS_LOG=debug DS_LOG_PATH=./secret.log secret encrypt db.env  # logs to a file instead of the terminal
```

Debug logs can name your files, recipients and the servers the CLI talks to, so read them before you share them.

## When someone's key changes

The CLI remembers the key it first saw for each person. If their key changes, it stops sending to them and opening their secrets until you accept the new one. Confirm it with them over a channel you trust, like a call:

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

Everything is encrypted on your computer with hybrid post-quantum encryption and signed by the sender. The encryption lives in the open source [DeepSecret Go SDK](https://github.com/deepsecret-io/deepsecret-go), and [PROTOCOL_V4.md](https://github.com/deepsecret-io/deepsecret-go/blob/main/PROTOCOL_V4.md) specifies it. The [documentation](https://docs.deepsecret.io/) explains the whole security model.

To report a vulnerability, please follow [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
