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

foreach ($VSRoot in
  "${Env:ProgramFiles(x86)}\MSBuild\14.0",
  "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\*\MSBuild\15.0",
  "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\*\MSBuild\Current")
{
  if (Get-Command -Name $VSRoot\Bin\MSBuild.exe `
        -CommandType Application `
        -ErrorAction SilentlyContinue)
  { break }
}

if (-not(Test-Path $VSRoot\Bin\MSBuild.exe)) {
  throw "MSBuild not found"
}
if ($VSRoot.Contains("14.0")) { $VSVersion = "v140"}
elseif ($VSRoot.Contains("2017")) { $VSVersion = "v141"}
elseif ($VSRoot.Contains("2019")) { $VSVersion = "v142"}
else { throw "MSBuild not found" }
Write-Host "Found MSBuild under $VSRoot ($VSVersion)"

& $VSRoot\Bin\MSBuild.exe `
  -noLogo `
  -maxCpuCount `
  -p:Platform=$Platform `
  -p:PlatformToolSet=$VSVersion `
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
