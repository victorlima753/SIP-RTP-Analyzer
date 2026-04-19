$ErrorActionPreference = "Stop"

$AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = "C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$Dist = Join-Path $AppDir "dist_v2"
$GuiName = "SIPRTPAnalyzerV2"
$FastIndexerDir = Join-Path $AppDir "v2\fast_indexer"
$FastIndexerExe = Join-Path $FastIndexerDir "target\release\siprtp_fast_indexer.exe"

if (-not (Test-Path $Python)) {
    $Python = "python"
}

$PythonRoot = Split-Path -Parent (& $Python -c "import sys; print(sys.executable)")
$TkSource = Join-Path $PythonRoot "tcl"
$TkRuntime = Join-Path $env:ProgramData "SIPRTPAnalyzer\tk_runtime"
$TkDest = Join-Path $TkRuntime "tcl"

Set-Location $AppDir
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

Write-Host "Preparando runtime Tcl/Tk..."
New-Item -ItemType Directory -Force -Path $TkRuntime | Out-Null
if ((Test-Path (Join-Path $TkSource "tcl8.6\init.tcl")) -and -not (Test-Path (Join-Path $TkDest "tcl8.6\init.tcl"))) {
    Remove-Item -LiteralPath $TkDest -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path $TkSource -Destination $TkDest -Recurse -Force
}
$env:SIPRTP_TK_RUNTIME = $TkRuntime
if (Test-Path (Join-Path $TkDest "tcl8.6\init.tcl")) {
    $env:TCL_LIBRARY = Join-Path $TkDest "tcl8.6"
}
if (Test-Path (Join-Path $TkDest "tk8.6\tk.tcl")) {
    $env:TK_LIBRARY = Join-Path $TkDest "tk8.6"
}

Write-Host "Compilando motor Rust..."
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Push-Location $FastIndexerDir
    cargo build --release
    Pop-Location
    if (Test-Path $FastIndexerExe) {
        Copy-Item -Path $FastIndexerExe -Destination (Join-Path $Dist "siprtp_fast_indexer.exe") -Force
    }
} else {
    Write-Warning "Cargo/Rust nao encontrado. O build seguira com fallback Python/TShark; instale Rust para gerar siprtp_fast_indexer.exe."
}

Write-Host "Gerando GUI V2..."
Remove-Item -LiteralPath (Join-Path $Dist "$GuiName.exe") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Dist "_internal") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Dist $GuiName) -Recurse -Force -ErrorAction SilentlyContinue

& $Python -m PyInstaller `
    --noconfirm `
    --onedir `
    --windowed `
    --name $GuiName `
    --distpath $Dist `
    --workpath (Join-Path $AppDir "build_v2") `
    --paths (Join-Path $AppDir "v2\app") `
    --hidden-import siprtp_v2_core `
    --hidden-import siprtp_v2_db `
    --hidden-import siprtp_v2_export `
    --hidden-import siprtp_v2_benchmark `
    --hidden-import siprtp_v2_performance `
    --hidden-import siprtp_v2_report `
    --hidden-import siprtp_v2_tk_runtime `
    --hidden-import tkinter `
    --hidden-import tkinter.filedialog `
    --hidden-import tkinter.messagebox `
    --hidden-import tkinter.ttk `
    --hidden-import _tkinter `
    --add-data "$TkSource;tcl" `
    v2\app\siprtp_v2_gui.py

Copy-Item -Path (Join-Path $Dist "$GuiName\*") -Destination $Dist -Recurse -Force
Remove-Item -LiteralPath (Join-Path $Dist $GuiName) -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Executavel GUI V2: $Dist\$GuiName.exe"
if (Test-Path (Join-Path $Dist "siprtp_fast_indexer.exe")) {
    Write-Host "Motor Rust:        $Dist\siprtp_fast_indexer.exe"
} else {
    Write-Host "Motor Rust:        nao gerado (Cargo/Rust ausente); GUI usara fallback Python/TShark."
}
