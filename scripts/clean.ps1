$ErrorActionPreference = "Stop"

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$rootPrefix = $root.TrimEnd('\') + '\'

function Get-CheckedTree([string]$Path) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean outside the project: $resolved"
    }
    # Validate every ancestor before enumeration, including the project itself.
    $ancestor = $resolved
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            $item = Get-Item -LiteralPath $ancestor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to traverse a reparse point: $ancestor"
            }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
    if (-not (Test-Path -LiteralPath $resolved)) { return }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($resolved)
    while ($pending.Count) {
        $item = Get-Item -LiteralPath $pending.Pop() -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to traverse a reparse point: $($item.FullName)"
        }
        $item
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) {
                $pending.Push($child.FullName)
            }
        }
    }
}

$cacheDirectories = @(foreach ($folder in @('src', 'tests', 'scripts')) {
    Get-CheckedTree (Join-Path $root $folder) |
        Where-Object { $_.PSIsContainer -and $_.Name -eq '__pycache__' }
})
# Include the known project-root cache without scanning user/output trees.
$cacheDirectories += @(Get-CheckedTree (Join-Path $root '__pycache__') |
    Where-Object { $_.PSIsContainer -and $_.Name -eq '__pycache__' })

# Validate all targets before deleting anything. Do not infer that tests/logs/
# unknown nested delivery folders are disposable merely from their names.
& (Join-Path $PSScriptRoot 'clean_intermediates.ps1')
# A cache folder name is not permission to remove EXE/INI/unknown files.
$cacheItems = @(foreach ($cache in $cacheDirectories) {
    Get-CheckedTree $cache.FullName
})
foreach ($file in $cacheItems | Where-Object { -not $_.PSIsContainer } |
    Sort-Object FullName -Unique) {
    if ($file.Extension.ToLowerInvariant() -in @('.pyc', '.pyo')) {
        Remove-Item -LiteralPath $file.FullName -Force
    }
}
foreach ($directory in $cacheItems | Where-Object PSIsContainer |
    Sort-Object FullName -Unique | Sort-Object { $_.FullName.Length } -Descending) {
    if ((Test-Path -LiteralPath $directory.FullName) -and
        @(Get-ChildItem -LiteralPath $directory.FullName -Force).Count -eq 0) {
        Remove-Item -LiteralPath $directory.FullName -Force
    }
}
Write-Host "Clean complete. Removed allowlisted Python bytecode files; retained unknown cache contents."
Write-Host "Preserved executables, INI, DLLs, data, logs, evidence, exports, and unknown delivery files."
