$ErrorActionPreference = 'Continue'
$root = Join-Path $env:TEMP ('lpm-env-qa-' + $PID)
New-Item -ItemType Directory -Force $root | Out-Null
$base = @('SystemRoot','WINDIR','COMSPEC','PATH','TEMP','TMP')
$cases = @(
  ($base + @('USERPROFILE')),
  ($base + @('LOCALAPPDATA')),
  ($base + @('APPDATA')),
  ($base + @('USERPROFILE','LOCALAPPDATA')),
  ($base + @('USERPROFILE','APPDATA')),
  ($base + @('LOCALAPPDATA','APPDATA')),
  ($base + @('USERPROFILE','LOCALAPPDATA','APPDATA'))
)
$i = 0
foreach ($keys in $cases) {
  $arguments = @('--protocol-version','2','--appcontainer-name',('LpmEnvQA' + $PID + '-' + $i),'--delete-appcontainer-profile','--env-clear','--stdio-stdin','null','--stdio-stdout','inherit','--stdio-stderr','inherit','--working-dir',$root,'--writable-dir',$root)
  foreach ($key in $keys) {
    $value = [Environment]::GetEnvironmentVariable($key)
    if ($null -ne $value) {$arguments += @('--env', ($key + '=' + $value))}
  }
  $arguments += @('--', (Join-Path $env:SystemRoot 'System32/cmd.exe'), '/d','/c','exit 0')
  Write-Output ('CASE ' + $i + ' KEYS ' + ($keys -join ','))
  & target/debug/lpm-sandbox-helper.exe @arguments
  Write-Output ('EXIT ' + $LASTEXITCODE)
  $i++
}
foreach ($key in @('USERPROFILE','LOCALAPPDATA','APPDATA')) {
  $arguments = @('--protocol-version','2','--appcontainer-name',('LpmMappedEnvQA' + $PID + '-' + $key),'--delete-appcontainer-profile','--env-clear','--stdio-stdin','null','--stdio-stdout','inherit','--stdio-stderr','inherit','--working-dir',$root,'--writable-dir',$root)
  foreach ($system in $base) {
    $arguments += @('--env',($system + '=' + [Environment]::GetEnvironmentVariable($system)))
  }
  $arguments += @('--env',($key + '=' + $root),'--',(Join-Path $env:SystemRoot 'System32/cmd.exe'),'/d','/c','exit 0')
  Write-Output ('MAPPED ' + $key)
  & target/debug/lpm-sandbox-helper.exe @arguments
  Write-Output ('EXIT ' + $LASTEXITCODE)
}
Remove-Item -Recurse -Force $root
exit 0
