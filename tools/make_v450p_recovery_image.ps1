param(
    [string]$InputDirectory = (Join-Path $PSScriptRoot "..\tmp-v450p-release"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\dist\wican-fw_obd_pro_v450p_full-recovery_16MB.bin")
)

$ErrorActionPreference = "Stop"

$flashSize = 16MB
$segments = @(
    @{ Name = "bootloader.bin"; Offset = 0x0000 },
    @{ Name = "partition-table.bin"; Offset = 0x8000 },
    @{ Name = "ota_data_initial.bin"; Offset = 0xD000 },
    @{ Name = "wican-fw_obd_pro_v450p.bin"; Offset = 0x10000 }
)

$image = [byte[]]::new($flashSize)
[Array]::Fill[byte]($image, 0xFF)

foreach ($segment in $segments) {
    $sourcePath = Join-Path $InputDirectory $segment.Name
    $bytes = [IO.File]::ReadAllBytes($sourcePath)
    $end = $segment.Offset + $bytes.Length
    if ($end -gt $flashSize) {
        throw "$($segment.Name) exceeds the 16 MB flash image."
    }
    [Array]::Copy($bytes, 0, $image, $segment.Offset, $bytes.Length)
}

$outputDirectory = Split-Path -Parent $OutputPath
[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
[IO.File]::WriteAllBytes($OutputPath, $image)

foreach ($segment in $segments) {
    $sourcePath = Join-Path $InputDirectory $segment.Name
    $source = [IO.File]::ReadAllBytes($sourcePath)
    $embedded = [byte[]]::new($source.Length)
    [Array]::Copy($image, $segment.Offset, $embedded, 0, $source.Length)
    if (-not [Linq.Enumerable]::SequenceEqual[byte]($source, $embedded)) {
        throw "Verification failed for $($segment.Name)."
    }
}

$hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
Write-Output "Created: $OutputPath"
Write-Output "Size: $flashSize bytes"
Write-Output "SHA256: $hash"
