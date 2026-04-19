@echo off
setlocal
set "APP_DIR=%~dp0"
set "SIPRTP_TK_RUNTIME=%ProgramData%\SIPRTPAnalyzer\tk_runtime"

if exist "%APP_DIR%dist_v2\SIPRTPAnalyzerV2.exe" (
  start "" "%APP_DIR%dist_v2\SIPRTPAnalyzerV2.exe"
  exit /b 0
)

echo Executavel V2 nao encontrado. Gerando build...
powershell -ExecutionPolicy Bypass -File "%APP_DIR%build_v2.ps1"

if exist "%APP_DIR%dist_v2\SIPRTPAnalyzerV2.exe" (
  start "" "%APP_DIR%dist_v2\SIPRTPAnalyzerV2.exe"
  exit /b 0
)

echo Falha ao gerar executavel V2.
pause
exit /b 1
