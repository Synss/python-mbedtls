<#
.SYNOPSIS
  Download mbedTLS

.PARAMETER Version
  The mbedTLS version to download

.PARAMETER DestinationPath
  Where the source code should be expanded.
#>

Param (
  [Parameter(Mandatory=$true)] $Version,
  [Parameter(Mandatory=$true)] $DestinationPath
)

$DebugPreference = "Continue"

$Name = "mbedtls"
$FileName = "$Name-$Version.zip"
$Uri = "https://github.com/ARMmbed/mbedtls/archive/$FileName"

if (Get-Command "New-TemporaryFile" -errorAction SilentlyContinue) {
  $TempFile = New-TemporaryFile
  if (-not(Test-Path $TempFile)) {
    throw "Could not create temporary file"
  } else {
    Write-Debug $TempFile
  }
} else {
  $TempFile = "download.tmp"
}

Write-Debug "Start download from $Uri"
try {
  Invoke-WebRequest -Uri $Uri -OutFile $TempFile
}
catch {
  Remove-Item $TempFile
}
Write-Debug "Done"

$TempZipFile = [io.path]::ChangeExtension($TempFile, "zip")
Move-Item $TempFile $TempZipFile

Write-Debug "Extract archive"
try {
  Expand-Archive -Path $TempZipFile -DestinationPath $DestinationPath
}
finally {
  Remove-Item $TempZipFile
}
Write-Debug "Done"

Move-Item $DestinationPath\$Name-$Name-$Version\* $DestinationPath
Remove-Item $DestinationPath\$Name-$Name-$Version

Write-Host "Done"
