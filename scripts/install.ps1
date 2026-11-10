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
# SHA256SUMS comes from the same release, so the check catches a damaged
# download, not a tampered release: RELEASING.md shows how to check the
# signature of SHA256SUMS and the build provenance as well. PowerShell
# downloads carry no mark of the web, so SmartScreen does not stop the
# unsigned secret.exe.

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

        $name = "secret_windows_$arch"
        $base = "https://github.com/$repo/releases/download/$version"
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('deepsecret-' + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tmp | Out-Null

        Write-Host "Downloading $name.zip ($version)..."
        $zip = Join-Path $tmp "$name.zip"
        $sums = Join-Path $tmp 'SHA256SUMS'
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$name.zip" -OutFile $zip
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

        Write-Host 'Checking it against SHA256SUMS...'
        # A line is "<hash>  <name>", or "<hash> *<name>" in binary mode.
        $line = Select-String -Path $sums -Pattern ('[ *]' + [regex]::Escape("$name.zip") + '$') | Select-Object -First 1
        if (-not $line) { throw "$name.zip is not listed in SHA256SUMS" }
        $want = $line.Line.Split(' ')[0]
        $got = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
        if ($got -ne $want) { throw "Checksum mismatch for $name.zip: expected $want, got $got. Do not use this download." }

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
