$ErrorActionPreference = 'Continue'
$root = Join-Path $env:TEMP ('lpm-env-qa-' + $PID)
New-Item -ItemType Directory -Force $root | Out-Null
$cases = @(
  @(),
  @('SystemRoot'),
  @('SystemRoot','WINDIR','COMSPEC','PATH','TEMP','TMP'),
  @('SystemRoot','WINDIR','COMSPEC','PATH','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA'),
  @('SystemRoot','WINDIR','COMSPEC','PATH','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA','ProgramData','ProgramFiles','ProgramFiles(x86)','SystemDrive')
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
Remove-Item -Recurse -Force $root
exit 0
