$ErrorActionPreference = 'Stop'
$root = 'C:\LpmSetupQA-' + $PID
$user = 'LpmSetup' + $PID
$password = 'Lpm-QA!' + [Guid]::NewGuid().ToString('N')
$credential = [PSCredential]::new("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $password -AsPlainText -Force))
$project = Join-Path $root 'project'
$tool = Join-Path $root 'node-tool'
$otherTool = Join-Path $root 'other-tool'
$setup = Join-Path $root 'qa_setup.exe'
$helper = Join-Path $root 'lpm-sandbox-helper.exe'
$counter = 0
function AsUser([string]$exe, [string[]]$arguments) {
 $script:counter++
 $stdout = Join-Path $root "stdout-$counter.txt"
 $stderr = Join-Path $root "stderr-$counter.txt"
 $quoted = ($arguments | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) -join ' '
 $process = Start-Process -FilePath $exe -ArgumentList $quoted -Credential $credential -LoadUserProfile -WorkingDirectory $project -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -Wait
 $out = Get-Content -Raw $stdout -ErrorAction SilentlyContinue
 $err = Get-Content -Raw $stderr -ErrorAction SilentlyContinue
 Write-Output "USER EXIT $($process.ExitCode) $out $err" | Out-Host
 return @{Code=$process.ExitCode; Out=$out; Err=$err}
}
try {
 New-LocalUser -Name $user -Password $credential.Password | Out-Null
 Add-LocalGroupMember -Group Users -Member $user
 $sid = (Get-LocalUser $user).SID.Value
 New-Item -ItemType Directory -Force $project,$tool,$otherTool | Out-Null
 Copy-Item target/debug/examples/qa_setup.exe $setup
 Copy-Item target/debug/lpm-sandbox-helper.exe $helper
 Copy-Item (Get-Command node).Source (Join-Path $tool 'node.exe')
 Set-Content (Join-Path $root 'unrelated.txt') 'outside-content'
 Set-Content (Join-Path $otherTool 'private.txt') 'other-tool-content'
 Set-Content (Join-Path $project '.env') 'FAKE_TEST_SECRET=blocked'
 # The normal Windows account can read all fixture inputs; the AppContainer must not.
 & icacls $root /grant ('*' + $sid + ':(OI)(CI)(RX)') | Out-Host
 & icacls $project /grant ('*' + $sid + ':(OI)(CI)(F)') | Out-Host
 @'
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
assert.equal(fs.realpathSync(__filename), __filename);
const parent = path.dirname(__dirname);
for (const [name, operation] of [
 ['LIST', () => fs.readdirSync(parent)],
 ['OUTSIDE_READ', () => fs.readFileSync(path.join(parent, 'unrelated.txt'))],
 ['OTHER_TOOL_READ', () => fs.readFileSync(path.join(parent, 'other-tool', 'private.txt'))],
 ['SECRET', () => fs.readFileSync(path.join(__dirname, '.env'))],
 ['WRITE_OUTSIDE', () => fs.writeFileSync(path.join(parent, 'outside-write.txt'), 'bad')],
]) {
 assert.throws(operation, error => ['EACCES','EPERM'].includes(error.code), name);
 console.log(name, 'DENIED');
}
fs.writeFileSync('hook-complete.txt','success');
console.log('HOOK_OK');
'@ | Set-Content (Join-Path $project 'hook.cjs')
 $preview = AsUser $setup @('preview',$project,'current',$tool)
 if ($preview.Code -ne 0) { throw 'standard preview failed' }
 $json = $preview.Out | ConvertFrom-Json
 if ($json.elevated -or $json.plan.user_sid -ne $sid) { throw 'not running as the expected standard user' }
 $refused = AsUser $setup @('apply',$project,'current',$tool)
 if ($refused.Code -eq 0 -or $refused.Err -notmatch 'administrator terminal') { throw 'standard setup must be refused' }
 $base = @('--protocol-version','2','--env-clear','--stdio-stdin','null','--stdio-stdout','inherit','--stdio-stderr','inherit','--working-dir',$project,'--writable-dir',$project,'--best-effort-readable-dir',$tool,'--secret-read-denied-path',(Join-Path $project '.env'),'--env',('SystemRoot=' + $env:SystemRoot),'--env',('LOCALAPPDATA=' + $project))
 $before = AsUser $helper ($base + @('--appcontainer-name',('LpmBefore' + $PID),'--',(Join-Path $tool 'node.exe'),'hook.cjs'))
 if ($before.Code -eq 0 -or $before.Err -notmatch 'sandbox-setup') { throw 'missing setup should be actionable' }
 for ($iteration=0; $iteration -lt 2; $iteration++) {
  $watch = [Diagnostics.Stopwatch]::StartNew()
  & $setup apply $project $sid $tool
  if ($LASTEXITCODE -ne 0) { throw 'administrator apply failed' }
  Write-Output "SETUP_MS $($watch.ElapsedMilliseconds)"
 }
 # Another configured tool must not be included in this invocation's capabilities.
 & $setup apply $project $sid $otherTool
 if ($LASTEXITCODE -ne 0) { throw 'other tool setup failed' }
 for ($iteration=0; $iteration -lt 3; $iteration++) {
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $after = AsUser $helper ($base + @('--appcontainer-name',('LpmAfter' + $PID + $iteration),'--',(Join-Path $tool 'node.exe'),'hook.cjs'))
  Write-Output "HOOK_MS $($watch.ElapsedMilliseconds)"
  if ($after.Code -ne 0 -or $after.Out -notmatch 'HOOK_OK') { throw 'standard Node hook failed' }
 }
 if ((Get-Content (Join-Path $project '.env')) -ne 'FAKE_TEST_SECRET=blocked') { throw 'secret restoration failed' }
 & $setup remove $project $sid $tool
 if ($LASTEXITCODE -ne 0) { throw 'administrator remove failed' }
 $removed = AsUser $helper ($base + @('--appcontainer-name',('LpmRemoved' + $PID),'--',(Join-Path $tool 'node.exe'),'hook.cjs'))
 if ($removed.Code -eq 0 -or $removed.Err -notmatch 'sandbox-setup') { throw 'removed setup should be required again' }
 Write-Output 'STANDARD_USER_SETUP_ALL_PASS'
} finally {
 if (Test-Path $setup) {
  & $setup remove $project $sid $tool $otherTool
 }
 Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
}
