@echo off
setlocal
set "KISIB_SOURCE_DIR=%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -STA -Command "$ErrorActionPreference='Stop'; try { $files=@(Get-ChildItem -LiteralPath (Join-Path $env:KISIB_SOURCE_DIR 'src') -Filter '*.cs' | Select-Object -ExpandProperty FullName); $files+=@(Get-ChildItem -LiteralPath (Join-Path $env:KISIB_SOURCE_DIR 'tests') -Filter '*.cs' | Select-Object -ExpandProperty FullName); Add-Type -Path $files -ReferencedAssemblies 'System.dll','System.Core.dll','System.Security.dll','System.Runtime.Serialization.dll','System.Xml.dll','System.Drawing.dll','System.Windows.Forms.dll'; $result=[Kisib.Verification]::Run($env:KISIB_SOURCE_DIR); exit $result } catch { Write-Host $_.Exception.ToString(); exit 1 }"
if errorlevel 1 (
  echo Windows verification did not pass.
) else (
  echo Automated checks finished. Manual enumeration gate is still required.
)
pause
endlocal
