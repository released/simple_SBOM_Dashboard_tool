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

$objectPath = Join-Path $root 'build\obj'
$objectItems = @(Get-CheckedTree $objectPath)
$cacheDirectories = @(foreach ($folder in @('src', 'tests', 'scripts')) {
    Get-CheckedTree (Join-Path $root $folder) |
        Where-Object { $_.PSIsContainer -and $_.Name -eq '__pycache__' }
})
# Validate all targets before deleting anything. Do not infer that tests/logs/
# unknown nested delivery folders are disposable merely from their names.
if ($objectItems.Count) { Remove-Item -LiteralPath $objectPath -Recurse -Force }
foreach ($cache in $cacheDirectories | Sort-Object FullName -Descending) {
    if (Test-Path -LiteralPath $cache.FullName) {
        Remove-Item -LiteralPath $cache.FullName -Recurse -Force
    }
}
Write-Host "Clean complete. Removed build/obj and source/test/script Python caches only."
Write-Host "Preserved executables, INI, DLLs, data, logs, evidence, exports, and unknown delivery files."
