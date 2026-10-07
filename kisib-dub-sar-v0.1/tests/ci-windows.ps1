param([string]$Project = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
$Project = [IO.Path]::GetFullPath($Project)
$resultDirectory = Join-Path $Project 'test-results'
New-Item -ItemType Directory -Force -Path $resultDirectory | Out-Null
$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
if (Test-Path -LiteralPath $sdk) {
  $sdkVersion = Get-ChildItem -LiteralPath $sdk -Directory | Sort-Object Name -Descending | Select-Object -First 1
  $header = Join-Path $sdkVersion.FullName 'um\wincrypt.h'
  if (Test-Path -LiteralPath $header) { Select-String -LiteralPath $header -SimpleMatch 'CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG' | ForEach-Object { Write-Host $_.Line.Trim() } }
}
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '64-bit .NET Framework compiler is unavailable.' }
$references = @('/reference:System.dll','/reference:System.Core.dll','/reference:System.Security.dll','/reference:System.Runtime.Serialization.dll','/reference:System.Xml.dll','/reference:System.Drawing.dll','/reference:System.Windows.Forms.dll')
$sources = @(Get-ChildItem -LiteralPath (Join-Path $Project 'src') -Filter '*.cs' | Select-Object -ExpandProperty FullName)
$tests = @(Get-ChildItem -LiteralPath (Join-Path $Project 'tests') -Filter '*.cs' | Select-Object -ExpandProperty FullName)
$testAssembly = Join-Path $resultDirectory 'Kisib.Verification.dll'
& $compiler /nologo /target:library /platform:anycpu /warn:4 "/out:$testAssembly" @references @sources @tests 2>&1 | Tee-Object -FilePath (Join-Path $resultDirectory 'compilation.txt')
if ($LASTEXITCODE -ne 0) { throw 'C# verification compilation failed.' }
Add-Type -Path $testAssembly
$result = [Kisib.Verification]::Run($Project)
if ($result -ne 0) { throw 'Windows verification suite failed.' }
$redTeam = [Kisib.RedTeamVerification]::Run($Project)
if ($redTeam -ne 0) { throw 'Adversarial verification failed.' }
$gui = [Kisib.GuiVerification]::Run($Project, $resultDirectory)
if ($gui -ne 0) { throw 'Native GUI smoke verification failed.' }
$nativeActivity = [Kisib.NativeActivityVerification]::Run($Project, $resultDirectory)
if ($nativeActivity -ne 0) { throw 'Native collector verification failed.' }
$binary = Join-Path $resultDirectory 'kisib.dub-sar.exe'
& $compiler /nologo /target:winexe /platform:anycpu /optimize+ /warn:4 "/win32manifest:$(Join-Path $Project 'app.manifest')" "/out:$binary" @references @sources
if ($LASTEXITCODE -ne 0) { throw 'Application executable compilation failed.' }
$environmentReport = [ordered]@{
  testedUtc = [DateTime]::UtcNow.ToString('o')
  os = [Environment]::OSVersion.VersionString
  architecture = $env:PROCESSOR_ARCHITECTURE
  processBits = [IntPtr]::Size * 8
  clr = [Environment]::Version.ToString()
  commit = $env:GITHUB_SHA
  executableSha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
}
$environmentReport | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $resultDirectory 'environment.json') -Encoding UTF8
