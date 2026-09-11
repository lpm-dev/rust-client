$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class ContainerSid {
 [DllImport("userenv.dll", CharSet=CharSet.Unicode)] public static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
 [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr value);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetKernelObjectSecurity(IntPtr handle, uint flags, byte[] descriptor);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LogonUser(string user, string domain, string password, uint type, uint provider, out IntPtr token);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
 [DllImport("advapi32.dll")] static extern bool RevertToSelf();
 public static void SetAcl(string path, byte[] descriptor) {
  IntPtr handle = CreateFile(path, 0x60000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
  if (handle == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  try { if (!SetKernelObjectSecurity(handle, 4, descriptor)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
  finally { CloseHandle(handle); }
 }
 public static int StandardUserWriteDac(string user, string password, string path) {
  IntPtr token;
  if (!LogonUser(user, ".", password, 2, 0, out token)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  try {
   if (!ImpersonateLoggedOnUser(token)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   try {
    IntPtr handle = CreateFile(path, 0x60000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
    if (handle == new IntPtr(-1)) return Marshal.GetLastWin32Error();
    CloseHandle(handle); return 0;
   } finally { RevertToSelf(); }
  } finally { CloseHandle(token); }
 }
}
'@
$root = Join-Path $env:TEMP ('lpm-ancestor-qa-' + $PID)
$project = Join-Path $root 'project'
New-Item -ItemType Directory -Force $project | Out-Null
Set-Content (Join-Path $root 'unrelated.txt') 'outside-content'
$node = (Get-Command node).Source
@'
const fs = require('fs');
console.log('REALPATH', fs.realpathSync(__filename));
const parent = require('path').dirname(__dirname);
for (const [name, operation] of [['LIST', () => fs.readdirSync(parent)], ['READ', () => fs.readFileSync(require('path').join(parent, 'unrelated.txt'))]]) {
 try { operation(); throw new Error(name + ' unexpectedly allowed'); }
 catch (error) { if (!['EPERM','EACCES'].includes(error.code)) throw error; console.log(name, 'DENIED'); }
}
'@ | Set-Content (Join-Path $project 'hook.cjs')
$name = 'LpmAncestorQA' + $PID
$base = @('--protocol-version','2','--appcontainer-name',$name,'--env-clear','--stdio-stdin','null','--stdio-stdout','inherit','--stdio-stderr','inherit','--working-dir',$project,'--writable-dir',$project,'--readable-dir',(Split-Path $node))
foreach ($key in @('SystemRoot','WINDIR','COMSPEC','PATH','TEMP','TMP')) { $base += @('--env',($key + '=' + [Environment]::GetEnvironmentVariable($key))) }
$base += @('--env',('LOCALAPPDATA=' + $project))
& target/debug/lpm-sandbox-helper.exe @base -- $node hook.cjs
Write-Output ('BEFORE ' + $LASTEXITCODE)
$pointer = [IntPtr]::Zero
if ([ContainerSid]::DeriveAppContainerSidFromAppContainerName($name, [ref]$pointer) -ne 0) { throw 'SID failure' }
$sid = [System.Security.Principal.SecurityIdentifier]::new($pointer)
[ContainerSid]::LocalFree($pointer) | Out-Null
$ancestors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in @($project, (Split-Path $node))) {
 $parent = [System.IO.Directory]::GetParent($entry)
 while ($parent) { [void]$ancestors.Add($parent.FullName); $parent = $parent.Parent }
}
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]160, 'None', 'None', 'Allow')
try {
 foreach ($path in $ancestors) {
  $acl = Get-Acl $path
  Write-Output ('ANCESTOR ' + $path + ' PROTECTED ' + $acl.AreAccessRulesProtected)
  $acl.AddAccessRule($rule)
  [ContainerSid]::SetAcl($path, $acl.GetSecurityDescriptorBinaryForm())
 }
 & target/debug/lpm-sandbox-helper.exe @base -- $node hook.cjs
 Write-Output ('AFTER ' + $LASTEXITCODE)
 if ($LASTEXITCODE -ne 0) { throw 'minimal metadata rights failed' }
} finally {
 foreach ($path in $ancestors) {
  $acl = Get-Acl $path
  $acl.RemoveAccessRuleSpecific($rule)
  [ContainerSid]::SetAcl($path, $acl.GetSecurityDescriptorBinaryForm())
 }
}
$user = 'LpmQA' + $PID
$password = 'Lpm-QA!' + [Guid]::NewGuid().ToString('N')
try {
 New-LocalUser -Name $user -Password (ConvertTo-SecureString $password -AsPlainText -Force) | Out-Null
 Add-LocalGroupMember -Group Users -Member $user
 Write-Output ('STANDARD_USER_ROOT_WRITE_DAC ' + [ContainerSid]::StandardUserWriteDac($user, $password, 'C:\'))
} finally { Remove-LocalUser -Name $user }
exit 0
