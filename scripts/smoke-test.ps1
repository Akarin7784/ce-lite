# M1+M2 端到端冒烟测试：跨进程 attach/读写/扫描/分配/反汇编/符号。
# 用法（在 pwsh 内）：& .\scripts\smoke-test.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'target\debug\ce-target.exe'
$serve  = Join-Path $root 'target\debug\ce-serve.exe'
$outFile  = Join-Path $root 'target\target-out.txt'
$respFile = Join-Path $root 'target\serve-out.txt'

Remove-Item $outFile, $respFile -ErrorAction SilentlyContinue

# 1. 启动目标进程，捕获地址与 pid
$proc = Start-Process -FilePath $target -RedirectStandardOutput $outFile -PassThru -NoNewWindow
Start-Sleep -Milliseconds 800
$addrHex = (Get-Content $outFile | Where-Object { $_ -match '^ADDR=0x' } | Select-Object -First 1) -replace '^ADDR=0x',''
$pid2 = $proc.Id
$addr = [Convert]::ToInt64($addrHex, 16)

$addr10   = $addr + 0x10
$addr777  = $addr + 0x200
$addrCode = $addr + 0x300
# mov eax,0x10; ret  => B8 10 00 00 00 C3
$code = [Convert]::ToBase64String([byte[]](0xB8, 0x10, 0x00, 0x00, 0x00, 0xC3))

Write-Host "target pid=$pid2 addr=0x$addrHex"

# 2. 全部请求（单一 ce-serve 进程，保持会话状态）
$reqs = @(
  ("{`"jsonrpc`":`"2.0`",`"id`":2,`"method`":`"process.attach`",`"params`":{`"pid`":$pid2}}"),
  ("{`"jsonrpc`":`"2.0`",`"id`":3,`"method`":`"memory.read`",`"params`":{`"address`":$addr10,`"size`":4}}"),
  '{"jsonrpc":"2.0","id":4,"method":"scan.new","params":{"value_type":"int32","scan_type":"exact","value":100}}',
  '{"jsonrpc":"2.0","id":5,"method":"scan.results","params":{"scan_id":1,"offset":0,"limit":200}}',
  ("{`"jsonrpc`":`"2.0`",`"id`":6,`"method`":`"memory.write`",`"params`":{`"address`":$addr10,`"bytes`":`"5wMAAA==`"}}"),
  '{"jsonrpc":"2.0","id":7,"method":"scan.next","params":{"scan_id":1,"scan_type":"changed","value":null}}',
  ("{`"jsonrpc`":`"2.0`",`"id`":8,`"method`":`"memory.read`",`"params`":{`"address`":$addr10,`"size`":4}}"),
  '{"jsonrpc":"2.0","id":9,"method":"scan.new","params":{"value_type":"bytes","scan_type":"exact","value":[222,173,190,239,202,254,186,190]}}',
  '{"jsonrpc":"2.0","id":10,"method":"scan.results","params":{"scan_id":2,"offset":0,"limit":200}}',
  '{"jsonrpc":"2.0","id":11,"method":"memory.alloc","params":{"size":4096}}',
  ("{`"jsonrpc`":`"2.0`",`"id`":12,`"method`":`"memory.write`",`"params`":{`"address`":$addrCode,`"bytes`":`"$code`"}}"),
  ("{`"jsonrpc`":`"2.0`",`"id`":13,`"method`":`"disasm`",`"params`":{`"address`":$addrCode,`"length`":6}}"),
  '{"jsonrpc":"2.0","id":14,"method":"symbols.resolve","params":{"name":"WriteFile"}}',
  '{"jsonrpc":"2.0","id":15,"method":"symbols.list","params":{"module":"ce-target.exe"}}',
  ("{`"jsonrpc`":`"2.0`",`"id`":17,`"method`":`"pointer.scan`",`"params`":{`"address`":$addr777,`"max_offset`":4096,`"max_depth`":3,`"pointer_size`":8}}"),
  '{"jsonrpc":"2.0","id":16,"method":"process.attach","params":{"pid":99999999}}'
)

$reqs | & $serve > $respFile

# 3. 打印响应
Get-Content $respFile

# 4. 清理
Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
