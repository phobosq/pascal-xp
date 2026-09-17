param(
    [Parameter(Mandatory=$true)][string]$AnalyzeHeadless,
    [Parameter(Mandatory=$true)][string]$XpBinary,
    [Parameter(Mandatory=$true)][string]$Win7Binary,
    [Parameter(Mandatory=$false)][string]$WorkDir = ".\work\ghidra",
    [Parameter(Mandatory=$false)][string]$ScriptDir = ".\ghidra"
)

$ErrorActionPreference = "Stop"

$work = [System.IO.Path]::GetFullPath($WorkDir)
$scripts = [System.IO.Path]::GetFullPath($ScriptDir)
New-Item -ItemType Directory -Force -Path $work | Out-Null

$xpJson = Join-Path $work "xp_program_facts.json"
$win7Json = Join-Path $work "win7_program_facts.json"
$compareJson = Join-Path $work "xp_vs_win7_program_facts.json"

function Invoke-GhidraExport {
    param(
        [string]$ProjectName,
        [string]$Binary,
        [string]$OutputJson
    )

    Write-Host "[ghidra] importing $Binary"
    & $AnalyzeHeadless $work $ProjectName `
        -import ([System.IO.Path]::GetFullPath($Binary)) `
        -scriptPath $scripts `
        -postScript ExportProgramFacts.py $OutputJson `
        -deleteProject

    if ($LASTEXITCODE -ne 0) {
        throw "Ghidra failed for $Binary (exit $LASTEXITCODE)"
    }
}

Invoke-GhidraExport -ProjectName "pascal_xp_recipient" -Binary $XpBinary -OutputJson $xpJson
Invoke-GhidraExport -ProjectName "pascal_win7_donor" -Binary $Win7Binary -OutputJson $win7Json

Write-Host "[compare] building $compareJson"
python .\scripts\compare_program_facts.py $xpJson $win7Json --out $compareJson
if ($LASTEXITCODE -ne 0) {
    throw "compare_program_facts.py failed"
}

Write-Host "Done. Reports:"
Write-Host "  $xpJson"
Write-Host "  $win7Json"
Write-Host "  $compareJson"
