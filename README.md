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
| Your AWS KMS key, for servers, containers, CI and AI agents (see [Servers, containers, CI and AI agents](#servers-containers-ci-and-ai-agents)) | `secret identity generate --kms-arn <KMS key ARN> --single` | nothing: the machine's AWS identity unlocks them |

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

### Servers, containers, CI and AI agents

A machine or container that decrypts on its own needs a key pair that opens with no prompt. Protect it with your own AWS KMS key: it then opens for the AWS identities your KMS key policy and IAM policies allow, on a machine that has its key file. Every unlock is a KMS `Decrypt` in your CloudTrail, and revoking that access stops every copy of the key file. The private keys never go to AWS (KMS only protects the key that opens the file), and DeepSecret never holds your KMS key.

That also means anyone who can change your key policy or IAM can give themselves access. For your own keys, a security key is stronger: use KMS for automation.

1. Give the automation its own DeepSecret account and an API key.
2. Create a customer managed, symmetric KMS key (`SYMMETRIC_DEFAULT`) used only for DeepSecret key files, and note its full key ARN: the CLI takes only that, never a key id or an alias, since an alias can be re-pointed.
3. Generate the key pair as that account, with AWS credentials allowed `kms:DescribeKey` and `kms:Encrypt` on the key:

   ```bash
   DS_API_KEY=... secret identity generate --kms-arn arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab --single
   ```

   It prints the `kms:Decrypt` policy statement for the machine that unlocks it, limited to the key file's encryption context (`deepsecret:purpose`, `deepsecret:fingerprint`, `deepsecret:account`, `deepsecret:slot`). Instead of `--single`, a second `--kms-arn` or `--recovery-code` keeps a way in if the KMS key becomes unusable.
4. Put the key file on the machine, from your CI's secret store, and check it there:

   ```bash
   printf '%s' "$DEEPSECRET_KEY_FILE" | secret identity import --stdin
   secret identity kms check
   ```

5. Decrypt with no prompt: `secret decrypt <secret-id> --output ./deploy.env`

In a container (an ECS task, an EKS pod), the AWS role comes from the platform (a task role, EKS Pod Identity or IRSA), and the key file from a mounted secret: run `secret identity import --file /run/secrets/deepsecret-key.json` when it starts. Import writes a copy readable only by the container's user, so the mount only has to be readable by that user, whatever its owner and mode.

`secret identity kms` lists, adds and removes KMS keys, manages the recovery code, and takes the protection off. AWS credentials come from the AWS default chain, or `--aws-profile`. For KMS the CLI always calls the key's own regional endpoint with the system's trusted certificates, whatever `AWS_ENDPOINT_URL` or a CA bundle says. The [documentation](https://docs.deepsecret.io/#aws-kms) covers key policies, GitHub Actions and revocation.

## Settings

The CLI keeps your login, keys and settings in `~/.deepsecret` (`%USERPROFILE%\.deepsecret` on Windows), readable only by you. It refuses to use a file there that other accounts on the computer can open, and tells you the command that fixes it.

| Variable | What it does |
|---|---|
| `DS_API_KEY` | The API key to use, for CI and scripts |
| `AWS_PROFILE` | The AWS profile for key pairs protected by AWS KMS (or `--aws-profile`) |
| `DS_LOG` | Log at this level: `trace`, `debug`, `info`, `warn` or `error`, or `json` |
| `DS_LOG_PATH` | Write the log to this file instead of the terminal |
| `DEEPSECRET_TMPDIR` | Where temporary and in-transit files go (must be private to you) |
| `NO_COLOR` | Turn off colors |

## Security

Everything is encrypted on your computer with hybrid post-quantum encryption and signed by the sender. The encryption lives in the open source [DeepSecret Go SDK](https://github.com/deepsecret-io/deepsecret-go), and [PROTOCOL_V4.md](https://github.com/deepsecret-io/deepsecret-go/blob/main/PROTOCOL_V4.md) specifies it. The [documentation](https://docs.deepsecret.io/) explains the whole security model.

To report a vulnerability, please follow [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
