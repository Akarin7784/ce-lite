// ce-lite → DeepSeek Harness 动态插件（Host 半区源码存档）。
//
// 这是 cordis_define 中 code.host 的权威副本。动态插件是进程内临时对象，
// 不随 DSH 重启保留，所以把源码落盘到 ce-lite 仓库以便复用。
//
// 运行时行为：
//   1. 通过 ctx.get('subprocess') 派生 ce-serve.exe（持久 stdio 守护进程）。
//   2. 在 ce-serve 的 stdout 上做行分隔 JSON-RPC 请求/响应关联。
//   3. 用 harness.defineTool + harness.registerTool 注册 12 个 ce_* 工具，
//      模型即可调用 attach / scan / read / write / disasm / symbols 等。
//   4. ctx.effect 在插件停止时终止子进程并反注册工具。
//
// 激活（在 DSH 会话中）：见 docs/design.md 的 DSH 集成一节。

return {
  apply(ctx) {
    const subprocess = ctx.get('subprocess')
    if (subprocess === undefined) {
      console.error('[ce-lite] subprocess service unavailable')
      return
    }

    const CEEXE = 'C:\\Users\\xueze\\Documents\\Plugin-developer\\ce-lite\\target\\debug\\ce-serve.exe'
    const CEWD = 'C:\\Users\\xueze\\Documents\\Plugin-developer\\ce-lite'

    let handle
    try {
      handle = subprocess.spawn({
        argv: [CEEXE],
        cwd: CEWD,
        stdio: { stdin: 'pipe', stdout: 'pipe', stderr: 'inherit' },
        graceMs: 2000,
      })
    } catch (e) {
      console.error('[ce-lite] spawn failed: ' + String(e))
      return
    }

    // ---- JSON-RPC 关联（行分隔） ----
    let nextId = 1
    const pending = new Map()
    let buf = ''

    handle.stdout.on('data', (chunk) => {
      buf += chunk.toString('utf8')
      let nl
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl)
        buf = buf.slice(nl + 1)
        if (line.trim() === '') continue
        let msg
        try { msg = JSON.parse(line) } catch (e) { continue }
        const entry = pending.get(msg.id)
        if (entry !== undefined) {
          pending.delete(msg.id)
          if (msg.error) entry.reject(new Error(msg.error.message))
          else entry.resolve(msg.result)
        }
      }
    })

    handle.done.then((outcome) => {
      for (const [id, entry] of pending) {
        pending.delete(id)
        entry.reject(new Error('ce-serve exited (code ' + outcome.exitCode + ')'))
      }
    })

    function rpc(method, params) {
      return new Promise((resolve, reject) => {
        const id = nextId++
        pending.set(id, { resolve, reject })
        handle.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n')
      })
    }

    // ---- 字节精确 base64（btoa/atob 是 UTF-8 感知的，会破坏非 ASCII 字节） ----
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    function bytesToB64(bytes) {
      let out = ''
      for (let i = 0; i < bytes.length; i += 3) {
        const b0 = bytes[i]
        const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0
        const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0
        const n = (b0 << 16) | (b1 << 8) | b2
        out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63]
        out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : '='
        out += i + 2 < bytes.length ? B64[n & 63] : '='
      }
      return out
    }
    function b64ToBytes(s) {
      const clean = s.replace(/[^A-Za-z0-9+/]/g, '')
      const bytes = []
      let acc = 0
      let accBits = 0
      for (let i = 0; i < clean.length; i++) {
        const v = B64.indexOf(clean[i])
        if (v < 0) continue
        acc = (acc << 6) | v
        accBits += 6
        if (accBits >= 8) {
          accBits -= 8
          bytes.push((acc >> accBits) & 0xff)
          acc &= (1 << accBits) - 1
        }
      }
      return bytes
    }
    function toHex(bytes) {
      let s = ''
      for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16)
      return s
    }

    // ---- 工具注册 ----
    const disposers = []
    function addTool(name, description, parameters, execute) {
      const def = harness.defineTool({
        name,
        description,
        parameters,
        output: {
          schema: { type: 'json' },
          render: (args, value) => [{ type: 'text', text: JSON.stringify(value ?? null) }],
        },
        execute,
      })
      disposers.push(harness.registerTool(ctx, def))
    }

    addTool('ce_process_list', 'List all processes on this machine (pid + name) for choosing a scan target.', {},
      async () => rpc('process.list', {}))

    addTool('ce_attach', 'Attach to a Windows process by pid for memory inspection.',
      { pid: { type: 'integer', description: 'Process id', required: true } },
      async (args) => rpc('process.attach', { pid: args.pid }))

    addTool('ce_regions', 'List readable/writable/executable memory regions of the attached process.', {},
      async () => rpc('memory.regions', {}))

    addTool('ce_read', 'Read memory from the attached process; returns bytes as a decimal array and hex string.',
      {
        address: { type: 'number', description: 'Absolute address', required: true },
        size: { type: 'integer', description: 'Bytes to read', required: true },
      },
      async (args) => {
        const r = await rpc('memory.read', { address: args.address, size: args.size })
        const bytes = b64ToBytes(r.bytes)
        return { address: args.address, size: bytes.length, hex: toHex(bytes), bytes }
      })

    addTool('ce_write', 'Write bytes into the attached process memory (bytes as a decimal array 0-255).',
      {
        address: { type: 'number', description: 'Absolute address', required: true },
        bytes: { type: 'array', items: { type: 'integer' }, description: 'Byte values to write', required: true },
      },
      async (args) => rpc('memory.write', { address: args.address, bytes: bytesToB64(args.bytes) }))

    addTool('ce_alloc', 'Allocate executable memory in the attached process (for code caves/patches).',
      { size: { type: 'integer', description: 'Bytes to allocate', required: true } },
      async (args) => rpc('memory.alloc', { size: args.size }))

    addTool('ce_memory_snapshot', 'Snapshot a memory region (save its bytes for later diff).',
      {
        address: { type: 'number', description: 'Absolute address', required: true },
        size: { type: 'integer', description: 'Bytes to snapshot (max 1MB)', required: true },
      },
      async (args) => rpc('memory.snapshot', { address: args.address, size: args.size }))

    addTool('ce_memory_diff', 'Diff a snapshotted memory region against its current bytes; returns changed offsets.',
      { snapshot_id: { type: 'integer', description: 'snapshot_id from ce_memory_snapshot', required: true } },
      async (args) => rpc('memory.diff', { snapshot_id: args.snapshot_id }))

    addTool('ce_scan_new', 'Start a memory scan (first scan). Returns scan_id for follow-ups.',
      {
        value_type: { type: 'string', description: 'byte|int16|int32|int64|float|double|string|bytes|binary', required: true },
        scan_type: { type: 'string', description: 'exact|increased|decreased|changed|unchanged|increased_by|decreased_by|bigger_than|smaller_than|unknown_initial', required: true },
        value: { type: 'json', description: 'Comparison value: number, string, byte array (AOB), or null' },
      },
      async (args) => rpc('scan.new', { value_type: args.value_type, scan_type: args.scan_type, value: args.value ?? null }))

    addTool('ce_scan_next', 'Narrow a scan (follow-up); re-reads candidates and filters.',
      {
        scan_id: { type: 'integer', description: 'scan_id from ce_scan_new/ce_scan_next', required: true },
        scan_type: { type: 'string', description: 'exact|changed|unchanged|increased|decreased|increased_by|decreased_by|bigger_than|smaller_than', required: true },
        value: { type: 'json', description: 'Comparison value (number/string/bytes/null)' },
      },
      async (args) => rpc('scan.next', { scan_id: args.scan_id, scan_type: args.scan_type, value: args.value ?? null }))

    addTool('ce_scan_results', 'Read paginated results of a scan.',
      {
        scan_id: { type: 'integer', description: 'scan_id', required: true },
        offset: { type: 'integer', description: '0-based result offset' },
        limit: { type: 'integer', description: 'Max results (default 1000)' },
      },
      async (args) => rpc('scan.results', { scan_id: args.scan_id, offset: args.offset ?? 0, limit: args.limit ?? 1000 }))

    addTool('ce_scan_close', 'Free a scan session.',
      { scan_id: { type: 'integer', description: 'scan_id', required: true } },
      async (args) => rpc('scan.close', { scan_id: args.scan_id }))

    addTool('ce_disasm', 'Disassemble machine code at an address (x64); returns instructions with bytes and text.',
      {
        address: { type: 'number', description: 'Absolute address', required: true },
        length: { type: 'integer', description: 'Bytes to decode (max 1MB)', required: true },
      },
      async (args) => rpc('disasm', { address: args.address, length: args.length }))

    addTool('ce_asm', 'Assemble x64 NASM-syntax code into machine bytes (mnemonic to bytes).',
      { code: { type: 'string', description: 'Assembly code, e.g. "mov eax, 0x10; ret"', required: true } },
      async (args) => rpc('asm', { code: args.code }))

    addTool('ce_symbols_resolve', 'Resolve an exported symbol name (e.g. "WriteFile") to an address.',
      { name: { type: 'string', description: 'Export name', required: true } },
      async (args) => rpc('symbols.resolve', { name: args.name }))

    addTool('ce_struct_define', 'Define a structure (named fields with type+offset) for interpreting memory.',
      {
        name: { type: 'string', description: 'Structure name', required: true },
        fields: { type: 'json', description: 'Array of {name, value_type, offset, size?}; value_type: byte|int16|int32|int64|float|double|string|bytes|binary', required: true },
      },
      async (args) => rpc('struct.define', { name: args.name, fields: args.fields }))

    addTool('ce_struct_read', 'Read a defined structure at an address; returns interpreted field values.',
      {
        name: { type: 'string', description: 'Structure name', required: true },
        address: { type: 'number', description: 'Absolute address', required: true },
      },
      async (args) => rpc('struct.read', { name: args.name, address: args.address }))

    addTool('ce_struct_list', 'List defined structures.', {},
      async () => rpc('struct.list', {}))

    addTool('ce_struct_delete', 'Delete a defined structure.',
      { name: { type: 'string', description: 'Structure name', required: true } },
      async (args) => rpc('struct.delete', { name: args.name }))

    addTool('ce_pointer_scan', 'Pointer scan: find multi-level pointer chains leading to a value address; static pointers resolve to module+offset.',
      {
        address: { type: 'number', description: 'The value address to find pointers to', required: true },
        max_offset: { type: 'integer', description: 'Max struct offset to allow (default 0x1000)' },
        max_depth: { type: 'integer', description: 'Max pointer levels (default 3)' },
        pointer_size: { type: 'integer', description: '4 or 8 bytes (default 8)' },
      },
      async (args) => rpc('pointer.scan', {
        address: args.address,
        max_offset: args.max_offset ?? 0x1000,
        max_depth: args.max_depth ?? 3,
        pointer_size: args.pointer_size ?? 8,
      }))

    addTool('ce_pointer_scan_start', 'Start a stateful pointer scan (first snapshot); returns scan_id for rescan denoising.',
      {
        address: { type: 'number', description: 'The value address to find pointers to', required: true },
        max_offset: { type: 'integer', description: 'Max struct offset to allow (default 0x1000)' },
        max_depth: { type: 'integer', description: 'Max pointer levels (default 3)' },
        pointer_size: { type: 'integer', description: '4 or 8 bytes (default 8)' },
      },
      async (args) => rpc('pointer.scan_start', {
        address: args.address,
        max_offset: args.max_offset ?? 0x1000,
        max_depth: args.max_depth ?? 3,
        pointer_size: args.pointer_size ?? 8,
      }))

    addTool('ce_pointer_rescan', 'Second snapshot: re-read each candidate pointer and drop unstable ones (denoise). Run after the value changed or time passed.',
      { scan_id: { type: 'integer', description: 'scan_id from ce_pointer_scan_start', required: true } },
      async (args) => rpc('pointer.rescan', { scan_id: args.scan_id }))

    addTool('ce_pointer_results', 'Read surviving pointer chains of a pointer scan (after rescan).',
      {
        scan_id: { type: 'integer', description: 'scan_id', required: true },
        offset: { type: 'integer', description: '0-based result offset' },
        limit: { type: 'integer', description: 'Max results (default 1000)' },
      },
      async (args) => rpc('pointer.results', { scan_id: args.scan_id, offset: args.offset ?? 0, limit: args.limit ?? 1000 }))

    addTool('ce_pointer_close', 'Free a pointer scan session.',
      { scan_id: { type: 'integer', description: 'scan_id', required: true } },
      async (args) => rpc('pointer.close', { scan_id: args.scan_id }))

    addTool('ce_debug_attach', 'Attach the debugger to a process (software breakpoints + register read).',
      { pid: { type: 'integer', description: 'Process id', required: true } },
      async (args) => rpc('debug.attach', { pid: args.pid }))

    addTool('ce_debug_detach', 'Detach the debugger from the current process.', {},
      async () => rpc('debug.detach', {}))

    addTool('ce_debug_breakpoint_set', 'Set a software breakpoint (INT3) at an address.',
      { address: { type: 'number', description: 'Absolute code address', required: true } },
      async (args) => rpc('debug.breakpoint_set', { address: args.address }))

    addTool('ce_debug_breakpoint_clear', 'Clear a software breakpoint (restore original byte).',
      { address: { type: 'number', description: 'Absolute code address', required: true } },
      async (args) => rpc('debug.breakpoint_clear', { address: args.address }))

    addTool('ce_debug_wait', 'Wait for a debug event (breakpoint hit / exception). Returns null on timeout.',
      { timeout_ms: { type: 'integer', description: 'Timeout in ms', required: true } },
      async (args) => rpc('debug.wait', { timeout_ms: args.timeout_ms }))

    addTool('ce_debug_continue', 'Resume the debugged process after a debug event.', {},
      async () => rpc('debug.continue', {}))

    addTool('ce_debug_registers', 'Read x64 registers of a thread (rip, rax..r15, eflags).',
      { thread_id: { type: 'integer', description: 'Thread id from a debug event', required: true } },
      async (args) => rpc('debug.registers', { thread_id: args.thread_id }))

    addTool('ce_debug_registers_set', 'Set x64 registers of a thread.',
      {
        thread_id: { type: 'integer', description: 'Thread id', required: true },
        registers: { type: 'json', description: 'Full register object (rip, rax, ...)', required: true },
      },
      async (args) => rpc('debug.registers_set', { thread_id: args.thread_id, registers: args.registers }))

    addTool('ce_debug_watchpoint_set', 'Set a hardware watchpoint on a data address (find what reads/writes it). Max 4.',
      {
        address: { type: 'number', description: 'Data address to watch', required: true },
        size: { type: 'integer', description: '1, 2, 4, or 8 bytes', required: true },
        on_read: { type: 'boolean', description: 'Trigger on read (default false)' },
        on_write: { type: 'boolean', description: 'Trigger on write (default true)' },
      },
      async (args) => rpc('debug.watchpoint_set', {
        address: args.address,
        size: args.size,
        on_read: args.on_read ?? false,
        on_write: args.on_write ?? true,
      }))

    addTool('ce_debug_watchpoint_clear', 'Clear a hardware watchpoint.',
      { address: { type: 'number', description: 'Data address', required: true } },
      async (args) => rpc('debug.watchpoint_clear', { address: args.address }))

    addTool('ce_debug_single_step', 'Single-step one instruction of the current thread (after a breakpoint/watchpoint).',
      { thread_id: { type: 'integer', description: 'Thread id from a debug event', required: true } },
      async (args) => rpc('debug.single_step', { thread_id: args.thread_id }))

    // ---- 清理 ----
    ctx.effect(() => () => {
      for (const d of disposers) { try { d() } catch (e) {} }
      if (handle !== undefined) { try { handle.terminate() } catch (e) {} }
    })
  },
}
