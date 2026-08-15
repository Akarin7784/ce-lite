# 指针扫描二次快照去噪端到端测试。
# 用法（在 pwsh 内）：& .\scripts\pointer-rescan-test.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'target\debug\ce-target.exe'
$serve  = Join-Path $root 'target\debug\ce-serve.exe'
$outFile = Join-Path $root 'target\target-out.txt'

Remove-Item $outFile -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath $target -RedirectStandardOutput $outFile -PassThru -NoNewWindow
Start-Sleep -Milliseconds 200
$addrHex = (Get-Content $outFile | Where-Object { $_ -match '^ADDR=0x' } | Select-Object -First 1) -replace '^ADDR=0x',''
$addr = [Convert]::ToInt64($addrHex, 16)
$pid2 = $proc.Id
$addr777 = $addr + 0x200
Write-Host "target pid=$pid2 value_addr=0x$($addr777.ToString('x'))"

# 交互式启动 ce-serve（有状态守护进程，需在两次请求间 sleep）
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $serve
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)

function Rpc([int]$id, [string]$method, [string]$params) {
    $p.StandardInput.WriteLine("{`"jsonrpc`":`"2.0`",`"id`":$id,`"method`":`"$method`",`"params`":$params}")
    $p.StandardInput.Flush()
    return $p.StandardOutput.ReadLine()
}

Rpc 1 "process.attach" "{`"pid`":$pid2}" | Out-Null

$r = Rpc 2 "pointer.scan_start" "{`"address`":$addr777,`"max_offset`":4096,`"max_depth`":2,`"pointer_size`":8}"
$scanId = ($r | ConvertFrom-Json).result.scan_id
$count0 = ($r | ConvertFrom-Json).result.count
Write-Host "scan_start: scan_id=$scanId count=$count0"

Write-Host "sleeping 2.5s (decoy 指针将在 2s 时翻转)..."
Start-Sleep -Milliseconds 2500

$r2 = Rpc 3 "pointer.rescan" "{`"scan_id`":$scanId}"
$count1 = ($r2 | ConvertFrom-Json).result.count
Write-Host "rescan: count=$count1  (去噪后应 < $count0)"

$r3 = Rpc 4 "pointer.results" "{`"scan_id`":$scanId,`"offset`":0,`"limit`":20}"
Write-Host "results: $($r3.Substring(0, [Math]::Min(600, $r3.Length)))"

Rpc 5 "pointer.close" "{`"scan_id`":$scanId}" | Out-Null
Write-Host "close done"

$p.Kill()
Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
