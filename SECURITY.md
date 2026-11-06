# Security policy

The CLI runs on your own machine, holds your login and your keys, and decrypts your secrets, and it is open so that anyone can check it. If you find a flaw, please tell us privately first.

## Reporting a vulnerability

Report it through GitHub: open this repository's [Security tab](https://github.com/deepsecret-io/cli/security) and choose **Report a vulnerability**. Only you and the maintainers can see the report.

Please do not open a public issue, pull request or discussion about a security problem. We will reply in the report, work on the fix with you there, and agree with you when to publish the details.

## What to report

Anything that lets someone get at a secret, a key or a login through the CLI. For example:

- **Local files:** the login token, API key or private keys are stored or left where another user can read them, or temporary or decrypted files get the wrong permissions.
- **Writing decrypted files:** a crafted secret writes outside the output folder, replaces a file it should not, or follows a planted link.
- **Sign-in:** the browser login can be hijacked, replayed or completed for the wrong account.
- **Credentials:** API keys, tokens or presigned URLs reach logs, debug output, error messages or the process list when the documented options are used.
- **Trust in keys:** the CLI sends to, or accepts a secret from, a key the user did not accept, or does not show a refused key clearly.
- **Untrusted text:** a secret name, file name or server message can inject terminal escape sequences or mislead the user about what they are opening.
- **Traffic:** the CLI can be made to send credentials to another host or over plaintext.
- **The installer and release process:** `scripts/install.sh` or a release archive can be tampered with unnoticed.

Flaws in the encryption, the protocol or key storage belong in [the SDK's repository](https://github.com/deepsecret-io/deepsecret-go). If you are not sure which of the two a problem belongs to, report it in either.

## What to include

- The version (`secret --version`) or commit you tested.
- What goes wrong and what an attacker gains.
- The steps to reproduce it.
- Your operating system and shell, if they matter.

Do not include real secrets, private keys, tokens or anyone else's data. `--debug` output is meant to be free of secrets, but please read it before you attach it.

## Supported versions

The CLI is before version 1.0, so security fixes go into the latest release only. Please check that the problem exists there or on `main` before you report it.

## Scope

- **This repository:** the CLI's code, its installer and its release scripts.
- **The hosted service** (`api.deepsecret.io`, `app.deepsecret.io` and `deepsecret.io`): use the same channel, here or in the SDK's repository.

This policy does not give permission to test the hosted service. The [Terms of Service](https://deepsecret.io/terms.html) forbid probing it without written authorization, so report what you noticed and ask before testing further. Never access or change anyone else's account or data.
