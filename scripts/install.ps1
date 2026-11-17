# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 DeepSecret
#
# Install the DeepSecret CLI on Windows. In PowerShell:
#
#   irm https://github.com/deepsecret-io/cli/releases/latest/download/install.ps1 | iex
#
# Finds the latest release (or the version in $env:DEEPSECRET_VERSION),
# downloads the archive for this computer (x64 or Arm), checks it against
# the release's SHA256SUMS, and installs secret.exe in
# %LOCALAPPDATA%\Programs\DeepSecret (or $env:INSTALL_DIR), adding that
# folder to your user PATH. It needs no administrator rights.
#
# SHA256SUMS comes from the same release, so on its own that check catches
# a damaged download, not a tampered release. So this also checks, with
# cosign, that this repository's Release workflow signed SHA256SUMS for
# the version, and stops if it did not. Without cosign it stops before it
# downloads anything and says how to install it; set
# $env:ALLOW_CHECKSUM_ONLY = '1' to install on the checksum alone, with a
# warning that the signature was not verified. RELEASING.md
# shows how to check the build provenance as well. PowerShell downloads
# carry no mark of the web, so SmartScreen does not stop the unsigned
# secret.exe.

# Everything runs in its own scope, and the one session-wide setting it
# changes (TLS 1.2 for Windows PowerShell 5.1) is put back, so nothing is
# left in the session that ran it with iex.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # Windows PowerShell downloads slowly while it draws progress
    $tls = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = $tls -bor [Net.SecurityProtocolType]::Tls12
    $tmp = $null
    try {
        $repo = 'deepsecret-io/cli'
        $version = $env:DEEPSECRET_VERSION
        if (-not $version) {
            # GitHub redirects releases/latest to the latest release's
            # page, whose address ends in its tag. No API call, so no rate
            # limit.
            $req = [Net.HttpWebRequest]::Create("https://github.com/$repo/releases/latest")
            $req.Method = 'HEAD'
            $req.AllowAutoRedirect = $false
            $resp = $req.GetResponse()
            try { $location = $resp.Headers['Location'] } finally { $resp.Close() }
            if (-not $location) { throw 'Could not find the latest release.' }
            $version = $location.TrimEnd('/').Split('/')[-1]
        }
        # Releases are vMAJOR.MINOR.PATCH, and the version goes into the
        # download address, so nothing else is accepted (\z, not $, so a
        # trailing newline does not pass).
        if ($version -notmatch '\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z') {
            throw "The version must look like v0.1.0, got: $version"
        }

        # The architecture of Windows itself, also from a 32-bit PowerShell.
        $osArch = $env:PROCESSOR_ARCHITEW6432
        if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITECTURE }
        $arch = switch ($osArch) {
            'AMD64' { 'amd64' }
            'ARM64' { 'arm64' }
            default { throw "This Windows architecture is not supported: $osArch" }
        }

        # cosign checks the signature of SHA256SUMS. Without it nothing
        # is downloaded, unless ALLOW_CHECKSUM_ONLY=1 accepts the checksum
        # alone: whoever can replace the archive can replace SHA256SUMS
        # with it. Only a program on the PATH counts, not an alias or a
        # function of this session, and only the value 1 accepts the
        # checksum alone, so nothing else is taken for a yes.
        $cosign = Get-Command -Name cosign -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cosign -and $env:ALLOW_CHECKSUM_ONLY -ne '1') {
            throw (@(
                'cosign is needed to verify the release signature, and it is not installed. Nothing was downloaded.'
                ''
                '  Why: the checksum file (SHA256SUMS) comes from the same place as the binary, so it'
                '  cannot prove who built it. Its signature can, and cosign checks the signature.'
                ''
                '  Install cosign v3, then run this again:'
                '    Windows:  save cosign-windows-amd64.exe from https://github.com/sigstore/cosign/releases/latest'
                '              as cosign.exe in a folder on your PATH'
                '    other:    https://docs.sigstore.dev/cosign/system_config/installation/'
                ''
                '  Or accept checksum-only verification, with no proof of who built the binary:'
                "    `$env:ALLOW_CHECKSUM_ONLY = '1'"
                '    irm https://github.com/deepsecret-io/cli/releases/latest/download/install.ps1 | iex'
            ) -join [Environment]::NewLine)
        }

        $name = "secret_windows_$arch"
        $base = "https://github.com/$repo/releases/download/$version"
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('deepsecret-' + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tmp | Out-Null

        Write-Host "Downloading $name.zip ($version)..."
        $zip = Join-Path $tmp "$name.zip"
        $sums = Join-Path $tmp 'SHA256SUMS'
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$name.zip" -OutFile $zip
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

        # The signature first: the checksums are trusted only once it
        # holds. It proves that this repository's Release workflow, run for
        # this version's tag, made SHA256SUMS.
        if ($cosign) {
            Write-Host 'Checking the signature of SHA256SUMS...'
            $bundle = Join-Path $tmp 'SHA256SUMS.sigstore.json'
            try {
                Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.sigstore.json" -OutFile $bundle
            }
            catch {
                throw "Could not download the signature of SHA256SUMS: $($_.Exception.Message)"
            }
            $cosignArgs = @(
                'verify-blob', $sums,
                '--bundle', $bundle,
                '--certificate-identity', "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$version",
                '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'
            )
            # cosign reports on stderr, also when the signature holds, and
            # with 'Stop' Windows PowerShell throws on what a program
            # writes there. So this one call runs with 'Continue', its
            # output is dropped, and its exit code decides. The exit code
            # starts as a failure, in case cosign does not run at all.
            $global:LASTEXITCODE = 1
            & {
                $ErrorActionPreference = 'Continue'
                & $cosign.Path @cosignArgs 2>&1 | Out-Null
            }
            if ($LASTEXITCODE -ne 0) {
                throw "SHA256SUMS is not signed by the DeepSecret CLI release workflow for $version. Do not use this download."
            }
        }

        Write-Host 'Checking it against SHA256SUMS...'
        # A line is "<hash>  <name>", or "<hash> *<name>" in binary mode.
        $line = Select-String -Path $sums -Pattern ('[ *]' + [regex]::Escape("$name.zip") + '$') | Select-Object -First 1
        if (-not $line) { throw "$name.zip is not listed in SHA256SUMS" }
        $want = $line.Line.Split(' ')[0]
        $got = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
        if ($got -ne $want) { throw "Checksum mismatch for $name.zip: expected $want, got $got. Do not use this download." }
        if (-not $cosign) {
            Write-Warning 'Only the checksum was verified. The release signature was NOT verified, because cosign is not installed and ALLOW_CHECKSUM_ONLY=1 is set. To verify it, see https://github.com/deepsecret-io/cli#check-the-release-signature'
        }

        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $exe = Join-Path $tmp "$name\secret.exe"
        if (-not (Test-Path -Path $exe -PathType Leaf)) { throw "The archive has no $name\secret.exe" }

        $dir = $env:INSTALL_DIR
        if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\DeepSecret' }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $dest = Join-Path $dir 'secret.exe'
        Copy-Item -Path $exe -Destination $dest -Force

        # On the user PATH for new terminals. The value is read and written
        # as stored, so entries such as %USERPROFILE%\bin stay unexpanded.
        $envKey = Get-Item -Path 'HKCU:\Environment'
        $raw = $envKey.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
        $kind = if ($envKey.GetValueNames() -contains 'Path') { $envKey.GetValueKind('Path') } else { 'ExpandString' }
        $parts = @($raw -split ';' | Where-Object { $_ })
        $listed = $parts | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') }
        if (-not $listed) {
            Set-ItemProperty -Path 'HKCU:\Environment' -Name 'Path' -Value (($parts + $dir) -join ';') -Type $kind
            # Setting a user variable through .NET tells running programs,
            # such as Explorer, that the environment changed.
            [Environment]::SetEnvironmentVariable('DEEPSECRET_INSTALLED', '1', 'User')
            [Environment]::SetEnvironmentVariable('DEEPSECRET_INSTALLED', $null, 'User')
            Write-Host "Added $dir to your PATH."
        }
        # And on this terminal's now.
        if (-not (@($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') })) { $env:Path = "$env:Path;$dir" }

        Write-Host "Installed $dest"
        & $dest --version
        if ($LASTEXITCODE -ne 0) { throw "$dest did not run (exit code $LASTEXITCODE)" }
        Write-Host "Run 'secret --help' to get started. Open a new terminal to use it everywhere."
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $tls
        if ($tmp) { Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue }
    }
}
