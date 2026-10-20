@echo off
setlocal
set "KISIB_BUILD_COMPILER=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%KISIB_BUILD_COMPILER%" set "KISIB_BUILD_COMPILER=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%KISIB_BUILD_COMPILER%" (
  echo Windows .NET Framework compiler was not found. Use Start.cmd instead.
  pause
  exit /b 1
)
if not exist "%~dp0bin" mkdir "%~dp0bin"
"%KISIB_BUILD_COMPILER%" /nologo /target:winexe /platform:anycpu /optimize+ /win32manifest:"%~dp0app.manifest" /out:"%~dp0bin\kisib.dub-sar.exe" /reference:System.dll /reference:System.Core.dll /reference:System.Security.dll /reference:System.Runtime.Serialization.dll /reference:System.Xml.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll "%~dp0src\*.cs"
if errorlevel 1 (
  pause
  exit /b 1
)
echo Built bin\kisib.dub-sar.exe
pause
endlocal
