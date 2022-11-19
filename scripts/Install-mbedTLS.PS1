<#

.SYNOPSIS
  Install mbedtls.

.PARAMETER Path
  The path to the mbedTLS source tree.

.PARAMETER StaticLibrary | DynamicLibrary
  Set the linkage.

.PARAMETER Win32 | x64
  Set the platform.

#>

Param (
  [Parameter(Position=0)]
  [String] $Path = ".",

  [Parameter(Mandatory)]
  [ValidateSet("StaticLibrary", "DynamicLibrary")]
  [String] $ConfigurationType,

  [Parameter()]
  [ValidateSet("Win32", "x64")]
  [String] $Platform = "x64"
)

$ProjectRoot = "$Path\visualc\VS2010"
$Configuration = "Release"

if (-not(Test-Path $ProjectRoot -PathType Container)) {
  throw "Project solution not found"
}

$MSBuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
  -latest `
  -requires Microsoft.Component.MSBuild `
  -find MSBuild\**\Bin\MSBuild.exe | select-object -first 1

if (-not(Test-Path $MSBuild)) {
  throw "MSBuild not found"
}

& $MSBuild `
  -noLogo `
  -maxCpuCount `
  -p:Platform=$Platform `
  -p:PlatformToolSet=v143 `
  -p:Configuration=$Configuration `
  -p:ConfigurationType=$ConfigurationType `
  -p:WholeProgramOptimization=False `
  $ProjectRoot\mbedTLS.sln

$lib = "$ProjectRoot\$Platform\$Configuration\"
if (Test-Path "$lib\mbedTLS.lib") {
  Write-Host "`n`nThe library is now available with`n"
  Write-Host `t`"'$env:LIB =' $(resolve-path $lib)`"
  Write-Host `t`"'$env:INCLUDE =' $(resolve-path $Path\include)`"
  Write-Host
}
