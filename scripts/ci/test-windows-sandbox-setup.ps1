param([string]$Binary = "target/debug/lpm-rs.exe")
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This test creates disposable Windows accounts and runs only on an isolated GitHub runner.' }
$Binary = (Resolve-Path $Binary).Path
$helperSource = Join-Path (Split-Path $Binary) 'lpm-sandbox-helper.exe'
$originalEnvironment = @{}
foreach ($key in @('PATH','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA','LPM_NO_UPDATE_CHECK','LPM_FORCE_FILE_AUTH','LPM_FORCE_FILE_VAULT','LPM_DISABLE_HOST_CLI_AUTH')) {
 $originalEnvironment[$key] = [Environment]::GetEnvironmentVariable($key)
}
$env:LPM_NO_UPDATE_CHECK = '1'
$env:LPM_FORCE_FILE_AUTH = '1'
$env:LPM_FORCE_FILE_VAULT = '1'
$env:LPM_DISABLE_HOST_CLI_AUTH = '1'
$root = 'C:\LpmSetupQA-' + $PID
$user = 'LpmSetup' + $PID
$password = 'Lpm-QA!' + [Guid]::NewGuid().ToString('N')
$credential = [PSCredential]::new("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $password -AsPlainText -Force))
$project = Join-Path $root 'project'
$tool = Join-Path $root 'node-tool'
$otherTool = Join-Path $root 'other-tool'
$setup = Join-Path $root 'lpm.exe'
$helper = Join-Path $root 'lpm-sandbox-helper.exe'
$counter = 0
$registryProcess = $null
function AsUser([string]$exe, [string[]]$arguments) {
 $script:counter++
 $stdout = Join-Path $root "stdout-$counter.txt"
 $stderr = Join-Path $root "stderr-$counter.txt"
 $quoted = ($arguments | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) -join ' '
 $process = Start-Process -FilePath $exe -ArgumentList $quoted -Credential $credential -LoadUserProfile -WorkingDirectory $project -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -Wait
 $out = Get-Content -Raw $stdout -ErrorAction SilentlyContinue
 $err = Get-Content -Raw $stderr -ErrorAction SilentlyContinue
 Write-Host "USER EXIT $($process.ExitCode) $out $err"
 return @{Code=$process.ExitCode; Out=$out; Err=$err}
}
try {
 New-LocalUser -Name $user -Password $credential.Password | Out-Null
 Add-LocalGroupMember -Group Users -Member $user
 $sid = (Get-LocalUser $user).SID.Value
 New-Item -ItemType Directory -Force $project,$tool,$otherTool | Out-Null
 Copy-Item $Binary $setup
 Copy-Item $helperSource $helper
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
 $bootstrap = AsUser "$env:SystemRoot\System32\whoami.exe" @('/user')
 if ($bootstrap.Code -ne 0) { throw 'standard-user logon failed' }
 $standardProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
 if (!$standardProfile.LocalPath) { throw 'standard-user profile was not loaded' }
 $env:USERPROFILE = $standardProfile.LocalPath
 $env:LOCALAPPDATA = Join-Path $standardProfile.LocalPath 'AppData\Local'
 $env:APPDATA = Join-Path $standardProfile.LocalPath 'AppData\Roaming'
 $env:TEMP = Join-Path $env:LOCALAPPDATA 'Temp'
 $env:TMP = $env:TEMP
 New-Item -ItemType Directory -Force $env:TEMP,$env:APPDATA | Out-Null
 $env:PATH = "$tool;$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0"
 $preview = AsUser $setup @('doctor','sandbox-setup','--project',$project,'--tool-dir',$tool,'--json')
 if ($preview.Code -ne 0) { throw 'standard preview failed' }
 $json = $preview.Out | ConvertFrom-Json
 if ($json.user_sid -ne $sid) { throw 'not running as the expected standard user' }
 $refused = AsUser $setup @('doctor','sandbox-setup','--project',$project,'--tool-dir',$tool,'--apply','--yes')
 if ($refused.Code -eq 0 -or $refused.Err -notmatch 'administrator terminal') { throw 'standard setup must be refused' }
 $base = @('--protocol-version','2','--env-clear','--stdio-stdin','null','--stdio-stdout','inherit','--stdio-stderr','inherit','--working-dir',$project,'--writable-dir',$project,'--readable-dir-best-effort',$tool,'--secret-read-deny',(Join-Path $project '.env'),'--env',('SystemRoot=' + $env:SystemRoot),'--env',('LOCALAPPDATA=' + $project))
 $before = AsUser $helper ($base + @('--appcontainer-name',('LpmBefore' + $PID),'--',(Join-Path $tool 'node.exe'),'hook.cjs'))
 if ($before.Code -eq 0 -or $before.Err -notmatch 'sandbox-setup') { throw 'missing setup should be actionable' }
 for ($iteration=0; $iteration -lt 2; $iteration++) {
  $watch = [Diagnostics.Stopwatch]::StartNew()
  & $setup @($json.apply_args) --yes --json
  if ($LASTEXITCODE -ne 0) { throw 'administrator apply failed' }
  Write-Output "SETUP_MS $($watch.ElapsedMilliseconds)"
 }
 # Another configured tool must not be included in this invocation's capabilities.
 & $setup doctor sandbox-setup --project $project --user-sid $sid --tool-dir $otherTool --apply --yes --json
 if ($LASTEXITCODE -ne 0) { throw 'other tool setup failed' }
 for ($iteration=0; $iteration -lt 3; $iteration++) {
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $after = AsUser $helper ($base + @('--appcontainer-name',('LpmAfter' + $PID + $iteration),'--',(Join-Path $tool 'node.exe'),'hook.cjs'))
  Write-Output "HOOK_MS $($watch.ElapsedMilliseconds)"
  if ($after.Code -ne 0 -or $after.Out -notmatch 'HOOK_OK') { throw 'standard Node hook failed' }
 }
 # A tool grant that overlaps the project must not override secret denial.
 & $setup doctor sandbox-setup --project $project --user-sid $sid --tool-dir $project --apply --yes --json
 if ($LASTEXITCODE -ne 0) { throw 'overlapping tool setup failed' }
 $overlap = AsUser $helper ($base + @('--readable-dir-best-effort',$project,'--appcontainer-name',('LpmOverlap' + $PID),'--',(Join-Path $tool 'node.exe'),'hook.cjs'))
 if ($overlap.Code -ne 0 -or $overlap.Out -notmatch 'HOOK_OK') { throw 'tool capability bypassed project-secret denial' }
 & $setup doctor sandbox-setup --project $project --user-sid $sid --tool-dir $project --remove --yes --json
 if ($LASTEXITCODE -ne 0) { throw 'overlapping tool removal failed' }
 & $setup @($json.apply_args) --yes --json
 if ($LASTEXITCODE -ne 0) { throw 'base setup restoration failed' }
 $registryScript = Join-Path $root 'registry.cjs'
 $registryPort = Join-Path $root 'registry-port.txt'
 $registryUpload = Join-Path $root 'registry-upload.json'
 @'
const fs = require('node:fs');
const http = require('node:http');
const server = http.createServer((req, res) => {
  const expected = req.url === '/lpm-sandbox-setup-fixture'
    && req.headers.authorization === 'Bearer publish-custom-registry-token';
  if (expected && req.method === 'PUT') {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      fs.writeFileSync(process.argv[3], Buffer.concat(chunks));
      res.writeHead(201, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ok: true}));
    });
    return;
  }
  res.writeHead(expected && req.method === 'GET' ? 404 : 400, {'Content-Type': 'application/json'});
  res.end(JSON.stringify({error: expected ? 'not found' : 'unexpected request'}));
});
server.listen(0, '127.0.0.1', () => fs.writeFileSync(process.argv[2], String(server.address().port)));
'@ | Set-Content $registryScript
 $registryProcess = Start-Process -FilePath (Join-Path $tool 'node.exe') -ArgumentList @($registryScript,$registryPort,$registryUpload) -PassThru
 $deadline = [DateTime]::UtcNow.AddSeconds(15)
 while (!(Test-Path $registryPort) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
 if (!(Test-Path $registryPort)) { throw 'disposable registry did not start' }
 $registryUrl = 'http://127.0.0.1:' + (Get-Content -Raw $registryPort)
 @{publish=@{npm=@{registry=$registryUrl}}} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $project 'lpm.json')
 $login = AsUser $setup @('login','--login-registry',$registryUrl,'--token','publish-custom-registry-token')
 if ($login.Code -ne 0) { throw 'disposable registry login failed' }
 $phases = @('prepublishOnly','prepack','prepare','postpack','publish','postpublish')
 $scripts = [ordered]@{}
 foreach ($phase in $phases) { $scripts[$phase] = "node publish-hook.cjs $phase" }
 @{name='lpm-sandbox-setup-fixture';version='1.0.0';license='MIT';main='index.js';files=@('index.js');scripts=$scripts} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $project 'package.json')
 Set-Content (Join-Path $project 'index.js') 'module.exports = 42'
 @'
const fs = require('fs');
const assert = require('node:assert/strict');
assert.throws(() => fs.readFileSync('.env'), error => ['EACCES','EPERM'].includes(error.code));
fs.appendFileSync('publish-phases.txt', process.argv[2] + '\n');
'@ | Set-Content (Join-Path $project 'publish-hook.cjs')
 $watch = [Diagnostics.Stopwatch]::StartNew()
 $publish = AsUser $setup @('publish','--npm','--dry-run','--yes')
 Write-Output "PUBLISH_SIX_HOOKS_MS $($watch.ElapsedMilliseconds)"
 if ($publish.Code -ne 0) { throw 'standard-user publish failed' }
 $actualPhases = @(Get-Content (Join-Path $project 'publish-phases.txt'))
 if (($actualPhases -join ',') -ne ($phases -join ',')) { throw "publish hooks did not run in order: $actualPhases" }
 if (Test-Path $registryUpload) { throw 'dry-run unexpectedly uploaded' }
 Remove-Item (Join-Path $project 'publish-phases.txt')
 $watch = [Diagnostics.Stopwatch]::StartNew()
 $publish = AsUser $setup @('publish','--npm','--yes')
 Write-Output "PUBLISH_UPLOAD_SIX_HOOKS_MS $($watch.ElapsedMilliseconds)"
 if ($publish.Code -ne 0) { throw 'standard-user publish upload failed' }
 $actualPhases = @(Get-Content (Join-Path $project 'publish-phases.txt'))
 if (($actualPhases -join ',') -ne ($phases -join ',')) { throw "upload hooks did not run in order: $actualPhases" }
 $uploaded = Get-Content -Raw $registryUpload | ConvertFrom-Json
 if ($uploaded.name -ne 'lpm-sandbox-setup-fixture' -or !$uploaded.versions.'1.0.0' -or !$uploaded._attachments) { throw 'registry did not receive a usable package' }
 if ((Get-Content (Join-Path $project '.env')) -ne 'FAKE_TEST_SECRET=blocked') { throw 'secret restoration failed' }
 & $setup @($json.apply_args | ForEach-Object { if ($_ -eq '--apply') { '--remove' } else { $_ } }) --yes --json
 if ($LASTEXITCODE -ne 0) { throw 'administrator remove failed' }
 $removed = AsUser $helper ($base + @('--appcontainer-name',('LpmRemoved' + $PID),'--',(Join-Path $tool 'node.exe'),'hook.cjs'))
 if ($removed.Code -eq 0 -or $removed.Err -notmatch 'sandbox-setup') { throw 'removed setup should be required again' }
 Write-Output 'STANDARD_USER_SETUP_ALL_PASS'
} finally {
 if ($registryProcess -and !$registryProcess.HasExited) { Stop-Process -Id $registryProcess.Id -Force }
 foreach ($key in $originalEnvironment.Keys) { [Environment]::SetEnvironmentVariable($key, $originalEnvironment[$key]) }
 if (Test-Path $setup) {
  if ($json) { & $setup @($json.apply_args | ForEach-Object { if ($_ -eq '--apply') { '--remove' } else { $_ } }) --yes --json }
  & $setup doctor sandbox-setup --project $project --user-sid $sid --tool-dir $tool --tool-dir $otherTool --remove --yes --json
 }
 Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
}
