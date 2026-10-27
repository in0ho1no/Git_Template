$ErrorActionPreference = 'Stop'
$path = Join-Path (Split-Path $PSScriptRoot -Parent) '.github\dependabot.yml'

try {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $utf8 = New-Object System.Text.UTF8Encoding($hasBom, $true)
    $offset = if ($hasBom) { 3 } else { 0 }
    $content = $utf8.GetString($bytes, $offset, $bytes.Length - $offset)
    $lines = [regex]::Split($content, '(?<=\n)')
    $entries = 0
    $targets = 0
    $inEntry = $false

    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*#') { continue }
        if ($line -match '^\s*-\s*package-ecosystem\s*:') {
            if ($line -notmatch '^  - package-ecosystem:\s*("[^"]+"|''[^'']+''|[^\s#]+)\s*(#.*)?\r?\n?$' -or
                ($inEntry -and $targets -ne $entries)) {
                throw 'Unsupported updates format or missing target-branch.'
            }
            $entries++
            $inEntry = $true
        }
        if ($line -match '^\s*(-\s*)?target-branch\s*:') {
            if (-not $inEntry -or $targets -ne ($entries - 1) -or
                $line -notmatch '^    target-branch:[ \t]*("[A-Za-z0-9._/-]+"|''[A-Za-z0-9._/-]+''|[A-Za-z0-9._/-]+)([ \t]*(#.*)?)(\r?\n)?$') {
                throw 'Unsupported or duplicate target-branch.'
            }
            $lines[$i] = [regex]::Replace($line, '^(    target-branch:[ \t]*)("[A-Za-z0-9._/-]+"|''[A-Za-z0-9._/-]+''|[A-Za-z0-9._/-]+)', '${1}"develop"')
            $targets++
        }
    }

    if ($entries -eq 0 -or $targets -ne $entries) {
        throw 'Each package-ecosystem must have a target-branch.'
    }
    $updated = [string]::Concat($lines)
    if ($updated -cne $content) {
        [System.IO.File]::WriteAllText($path, $updated, $utf8)
        Write-Host '[OK] Dependabot targets changed to develop.'
    } else {
        Write-Host '[OK] Dependabot targets are already develop.'
    }
} catch {
    [Console]::Error.WriteLine("[ERROR] Failed to update Dependabot configuration: $($_.Exception.Message)")
    exit 1
}
