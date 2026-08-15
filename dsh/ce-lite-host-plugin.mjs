// ce-lite → DeepSeek Harness 宿主插件（host composition）。
//
// 本文件是 dsh/celit-plugin.js（会话动态插件）的宿主常驻版本：
// 由 ~/.dsh/profiles/web/cordis.patch.yml 通过 `insert` 挂载，
// 任何会话都可用（不随 DSH 会话重启丢失，host 进程常驻）。
//
// 与动态插件的差异：defineTool 来自 @deepseek-ai/dsh-tools（ESM），
// 工具经 ctx.tools.register 注册（返回 disposer），subprocess 服务注入访问。

import { defineTool } from "@deepseek-ai/dsh-tools"

export const name = "ce-lite"
export const inject = ["tools", "subprocess"]
export function apply(ctx) {
  const CEEXE = "C:\\Users\\xueze\\Documents\\Plugin-developer\\ce-lite\\target\\debug\\ce-serve.exe"
  const CEWD = "C:\\Users\\xueze\\Documents\\Plugin-developer\\ce-lite"

  let handle
  try {
    handle = ctx.subprocess.spawn({
      argv: [CEEXE],
      cwd: CEWD,
      stdio: { stdin: "pipe", stdout: "pipe", stderr: "inherit" },
      graceMs: 2000,
    })
  } catch (e) {
    console.error("[ce-lite] spawn failed: " + String(e))
    return
  }

  let nextId = 1
  const pending = new Map()
  let buf = ""

  handle.stdout.on("data", (chunk) => {
    buf += chunk.toString("utf8")
    let nl
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl)
      buf = buf.slice(nl + 1)
      if (line.trim() === "") continue
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
      entry.reject(new Error("ce-serve exited (code " + outcome.exitCode + ")"))
    }
  })

  function rpc(method, params) {
    return new Promise((resolve, reject) => {
      const id = nextId++
      pending.set(id, { resolve, reject })
      handle.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n")
    })
  }

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  function bytesToB64(bytes) {
    let out = ""
    for (let i = 0; i < bytes.length; i += 3) {
      const b0 = bytes[i]
      const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0
      const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0
      const n = (b0 << 16) | (b1 << 8) | b2
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63]
      out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : "="
      out += i + 2 < bytes.length ? B64[n & 63] : "="
    }
    return out
  }
  function b64ToBytes(s) {
    const clean = s.replace(/[^A-Za-z0-9+/]/g, "")
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
    let s = ""
    for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16)
    return s
  }

  const disposers = []
  function addTool(toolName, description, parameters, execute, render) {
    const def = defineTool({
      name: toolName,
      description,
      parameters,
      output: {
        schema: { type: "json" },
        render: render || ((args, value) => [{ type: "text", text: JSON.stringify(value ?? null) }]),
      },
      execute,
    })
    disposers.push(ctx.tools.register(def))
  }

  function hexdump(bytes, base) {
    const lines = []
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16)
      const hex = chunk.map((b) => (b < 16 ? "0" : "") + b.toString(16)).join(" ")
      const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("")
      const addr = (base + i).toString(16).padStart(8, "0")
      lines.push(addr + "  " + hex.padEnd(47) + "  " + ascii)
    }
    return lines.join("\n")
  }
  const hexRender = (args, value) => {
    if (value === null || value === undefined || !value.bytes) return [{ type: "text", text: JSON.stringify(value ?? null) }]
    return [{ type: "text", text: "address=0x" + value.address.toString(16) + " size=" + value.bytes.length + "\n" + hexdump(value.bytes, value.address) }]
  }

  addTool("ce_process_list", "List all processes on this machine (pid + name) for choosing a scan target.", {},
    async () => rpc("process.list", {}))

  addTool("ce_protect_status", "Detect known anti-cheat software running on this machine (EAC, BattlEye, Vanguard, Tencent ACE, GameGuard, etc.). Call BEFORE attaching to a target: if protected=true, attaching may fail or trigger the anti-cheat.",
    {},
    async () => rpc("protect.status", {}))

  addTool("ce_attach", "Attach to a Windows process by pid for memory inspection.",
    { pid: { type: "integer", description: "Process id", required: true } },
    async (args) => rpc("process.attach", { pid: args.pid }))

  addTool("ce_regions", "List readable/writable/executable memory regions of the attached process.", {},
    async () => rpc("memory.regions", {}))

  addTool("ce_read", "Read memory from the attached process; renders as a hex dump with ASCII sidebar.",
    {
      address: { type: "number", description: "Absolute address", required: true },
      size: { type: "integer", description: "Bytes to read", required: true },
    },
    async (args) => {
      const r = await rpc("memory.read", { address: args.address, size: args.size })
      const bytes = b64ToBytes(r.bytes)
      return { address: args.address, size: bytes.length, hex: toHex(bytes), bytes }
    },
    hexRender)

  addTool("ce_write", "Write bytes into the attached process memory (bytes as a decimal array 0-255).",
    {
      address: { type: "number", description: "Absolute address", required: true },
      bytes: { type: "array", items: { type: "integer" }, description: "Byte values to write", required: true },
    },
    async (args) => rpc("memory.write", { address: args.address, bytes: bytesToB64(args.bytes) }))

  addTool("ce_alloc", "Allocate executable memory in the attached process (for code caves/patches).",
    { size: { type: "integer", description: "Bytes to allocate", required: true } },
    async (args) => rpc("memory.alloc", { size: args.size }))

  addTool("ce_memory_snapshot", "Snapshot a memory region (save its bytes for later diff).",
    {
      address: { type: "number", description: "Absolute address", required: true },
      size: { type: "integer", description: "Bytes to snapshot (max 1MB)", required: true },
    },
    async (args) => rpc("memory.snapshot", { address: args.address, size: args.size }))

  addTool("ce_memory_diff", "Diff a snapshotted memory region against its current bytes; returns changed offsets.",
    { snapshot_id: { type: "integer", description: "snapshot_id from ce_memory_snapshot", required: true } },
    async (args) => rpc("memory.diff", { snapshot_id: args.snapshot_id }))

  addTool("ce_scan_new", "Start a memory scan (first scan). Returns scan_id for follow-ups. Advanced: mask (AOB wildcards), min/max (between), xor_key (XOR scan).",
    {
      value_type: { type: "string", description: "byte|int16|int32|int64|float|double|string|bytes|binary", required: true },
      scan_type: { type: "string", description: "exact|increased|decreased|changed|unchanged|increased_by|decreased_by|bigger_than|smaller_than|between|rounded|unknown_initial", required: true },
      value: { type: "json", description: "Comparison value: number, string, byte array (AOB), or null" },
      mask: { type: "json", description: "AOB wildcard mask: 255=must match, 0=wildcard (same length as value)" },
      min: { type: "number", description: "between scan lower bound (inclusive)" },
      max: { type: "number", description: "between scan upper bound (inclusive)" },
      xor_key: { type: "integer", description: "XOR scan key: bytes are XORed with this before comparing" },
    },
    async (args) => rpc("scan.new", {
      value_type: args.value_type, scan_type: args.scan_type, value: args.value ?? null,
      mask: args.mask ?? null, min: args.min ?? null, max: args.max ?? null, xor_key: args.xor_key ?? null,
    }))

  addTool("ce_scan_next", "Narrow a scan (follow-up); re-reads candidates and filters.",
    {
      scan_id: { type: "integer", description: "scan_id from ce_scan_new/ce_scan_next", required: true },
      scan_type: { type: "string", description: "exact|changed|unchanged|increased|decreased|increased_by|decreased_by|bigger_than|smaller_than|between|rounded", required: true },
      value: { type: "json", description: "Comparison value (number/string/bytes/null)" },
      mask: { type: "json", description: "AOB wildcard mask (with bytes value)" },
      min: { type: "number", description: "between lower bound" },
      max: { type: "number", description: "between upper bound" },
      xor_key: { type: "integer", description: "XOR key" },
    },
    async (args) => rpc("scan.next", {
      scan_id: args.scan_id, scan_type: args.scan_type, value: args.value ?? null,
      mask: args.mask ?? null, min: args.min ?? null, max: args.max ?? null, xor_key: args.xor_key ?? null,
    }))

  addTool("ce_scan_results", "Read paginated results of a scan.",
    {
      scan_id: { type: "integer", description: "scan_id", required: true },
      offset: { type: "integer", description: "0-based result offset" },
      limit: { type: "integer", description: "Max results (default 1000)" },
    },
    async (args) => rpc("scan.results", { scan_id: args.scan_id, offset: args.offset ?? 0, limit: args.limit ?? 1000 }))

  addTool("ce_scan_close", "Free a scan session.",
    { scan_id: { type: "integer", description: "scan_id", required: true } },
    async (args) => rpc("scan.close", { scan_id: args.scan_id }))

  addTool("ce_disasm", "Disassemble machine code at an address (x64); returns instructions with bytes and text.",
    {
      address: { type: "number", description: "Absolute address", required: true },
      length: { type: "integer", description: "Bytes to decode (max 1MB)", required: true },
    },
    async (args) => rpc("disasm", { address: args.address, length: args.length }))

  addTool("ce_disasm_xrefs", 'Find all direct CALL instructions targeting an address ("who calls this function"). Scans executable regions.',
    {
      address: { type: "number", description: "Target address", required: true },
      module: { type: "string", description: "Optional module name/path to limit the scan" },
      limit: { type: "integer", description: "Max results (default 100)" },
    },
    async (args) => rpc("disasm.xrefs", { address: args.address, module: args.module ?? null, limit: args.limit ?? 100 }))

  addTool("ce_disasm_function", "Identify a function boundary around an address: walks back to the prologue and forward to ret.",
    {
      address: { type: "number", description: "Address inside the function", required: true },
      max_back: { type: "integer", description: "Bytes to walk back looking for the start (default 256)" },
      max_len: { type: "integer", description: "Max bytes to disassemble forward (default 4096)" },
    },
    async (args) => rpc("disasm.function", { address: args.address, max_back: args.max_back ?? 256, max_len: args.max_len ?? 4096 }))

  addTool("ce_asm", 'Assemble x64 NASM-syntax code into machine bytes (mnemonic to bytes).',
    { code: { type: "string", description: "Assembly code, e.g. \"mov eax, 0x10; ret\"", required: true } },
    async (args) => rpc("asm", { code: args.code }))

  addTool("ce_symbols_resolve", 'Resolve an exported symbol name (e.g. "WriteFile") to an address.',
    { name: { type: "string", description: "Export name", required: true } },
    async (args) => rpc("symbols.resolve", { name: args.name }))

  addTool("ce_symbols_pdb_resolve", "Resolve an address to a function name via PDB/DbgHelp symbols (name may be null if no PDB).",
    { address: { type: "number", description: "Absolute address", required: true } },
    async (args) => rpc("symbols.pdb_resolve", { address: args.address }))

  addTool("ce_module_aob_scan", 'Scan for an AOB byte pattern with ? wildcards (CE style, e.g. "DE ?? BE EF") across readable memory or one module.',
    {
      pattern: { type: "string", description: "Pattern string, e.g. \"DE ?? BE EF\"", required: true },
      module: { type: "string", description: "Optional module name/path to limit the search" },
    },
    async (args) => rpc("module.aob_scan", { pattern: args.pattern, module: args.module ?? null }))

  addTool("ce_struct_define", "Define a structure (named fields with type+offset) for interpreting memory.",
    {
      name: { type: "string", description: "Structure name", required: true },
      fields: { type: "json", description: "Array of {name, value_type, offset, size?}; value_type: byte|int16|int32|int64|float|double|string|bytes|binary", required: true },
    },
    async (args) => rpc("struct.define", { name: args.name, fields: args.fields }))

  addTool("ce_struct_read", "Read a defined structure at an address; returns interpreted field values.",
    {
      name: { type: "string", description: "Structure name", required: true },
      address: { type: "number", description: "Absolute address", required: true },
    },
    async (args) => rpc("struct.read", { name: args.name, address: args.address }))

  addTool("ce_struct_list", "List defined structures.", {},
    async () => rpc("struct.list", {}))

  addTool("ce_struct_delete", "Delete a defined structure.",
    { name: { type: "string", description: "Structure name", required: true } },
    async (args) => rpc("struct.delete", { name: args.name }))

  addTool("ce_session_save", "Export the whole analysis session (structs, pointer chains, patches, freezes, hooks) as a base64 blob for later ce_session_load.",
    {},
    async () => rpc("session.save", {}))

  addTool("ce_session_load", "Restore a previously saved session (base64 from ce_session_save).",
    { data: { type: "string", description: "base64 session blob from ce_session_save", required: true } },
    async (args) => rpc("session.load", { data: args.data }))

  addTool("ce_pointer_scan", "Pointer scan: find multi-level pointer chains leading to a value address; static pointers resolve to module+offset.",
    {
      address: { type: "number", description: "The value address to find pointers to", required: true },
      max_offset: { type: "integer", description: "Max struct offset to allow (default 0x1000)" },
      max_depth: { type: "integer", description: "Max pointer levels (default 3)" },
      pointer_size: { type: "integer", description: "4 or 8 bytes (default 8)" },
    },
    async (args) => rpc("pointer.scan", {
      address: args.address,
      max_offset: args.max_offset ?? 0x1000,
      max_depth: args.max_depth ?? 3,
      pointer_size: args.pointer_size ?? 8,
    }))

  addTool("ce_pointer_scan_start", "Start a stateful pointer scan (first snapshot); returns scan_id for rescan denoising.",
    {
      address: { type: "number", description: "The value address to find pointers to", required: true },
      max_offset: { type: "integer", description: "Max struct offset to allow (default 0x1000)" },
      max_depth: { type: "integer", description: "Max pointer levels (default 3)" },
      pointer_size: { type: "integer", description: "4 or 8 bytes (default 8)" },
    },
    async (args) => rpc("pointer.scan_start", {
      address: args.address,
      max_offset: args.max_offset ?? 0x1000,
      max_depth: args.max_depth ?? 3,
      pointer_size: args.pointer_size ?? 8,
    }))

  addTool("ce_pointer_rescan", "Second snapshot: re-read each candidate pointer and drop unstable ones (denoise). Run after the value changed or time passed.",
    { scan_id: { type: "integer", description: "scan_id from ce_pointer_scan_start", required: true } },
    async (args) => rpc("pointer.rescan", { scan_id: args.scan_id }))

  addTool("ce_pointer_results", "Read surviving pointer chains of a pointer scan (after rescan).",
    {
      scan_id: { type: "integer", description: "scan_id", required: true },
      offset: { type: "integer", description: "0-based result offset" },
      limit: { type: "integer", description: "Max results (default 1000)" },
    },
    async (args) => rpc("pointer.results", { scan_id: args.scan_id, offset: args.offset ?? 0, limit: args.limit ?? 1000 }))

  addTool("ce_pointer_close", "Free a pointer scan session.",
    { scan_id: { type: "integer", description: "scan_id", required: true } },
    async (args) => rpc("pointer.close", { scan_id: args.scan_id }))

  addTool("ce_pointer_analyze", "Analyze a pointer scan: offset clustering (most frequent struct offsets) and union grouping (chains sharing the same offset path).",
    { scan_id: { type: "integer", description: "scan_id", required: true } },
    async (args) => rpc("pointer.analyze", { scan_id: args.scan_id }))

  addTool("ce_pointer_struct_spawn", "Generate candidate structure fields from a pointer scan (structure spawn): deduped offsets as int64 fields for struct.define.",
    { scan_id: { type: "integer", description: "scan_id", required: true } },
    async (args) => rpc("pointer.struct_spawn", { scan_id: args.scan_id }))

  addTool("ce_debug_attach", "Attach the debugger to a process (software breakpoints + register read).",
    { pid: { type: "integer", description: "Process id", required: true } },
    async (args) => rpc("debug.attach", { pid: args.pid }))

  addTool("ce_debug_detach", "Detach the debugger from the current process.", {},
    async () => rpc("debug.detach", {}))

  addTool("ce_debug_breakpoint_set", "Set a software breakpoint (INT3) at an address.",
    { address: { type: "number", description: "Absolute code address", required: true } },
    async (args) => rpc("debug.breakpoint_set", { address: args.address }))

  addTool("ce_debug_breakpoint_clear", "Clear a software breakpoint (restore original byte).",
    { address: { type: "number", description: "Absolute code address", required: true } },
    async (args) => rpc("debug.breakpoint_clear", { address: args.address }))

  addTool("ce_debug_wait", "Wait for a debug event (breakpoint hit / exception). Returns null on timeout.",
    { timeout_ms: { type: "integer", description: "Timeout in ms", required: true } },
    async (args) => rpc("debug.wait", { timeout_ms: args.timeout_ms }))

  addTool("ce_debug_continue", "Resume the debugged process after a debug event.", {},
    async () => rpc("debug.continue", {}))

  addTool("ce_debug_registers", "Read x64 registers of a thread (rip, rax..r15, eflags).",
    { thread_id: { type: "integer", description: "Thread id from a debug event", required: true } },
    async (args) => rpc("debug.registers", { thread_id: args.thread_id }))

  addTool("ce_debug_registers_set", "Set x64 registers of a thread.",
    {
      thread_id: { type: "integer", description: "Thread id", required: true },
      registers: { type: "json", description: "Full register object (rip, rax, ...)", required: true },
    },
    async (args) => rpc("debug.registers_set", { thread_id: args.thread_id, registers: args.registers }))

  addTool("ce_debug_watchpoint_set", "Set a hardware watchpoint on a data address (find what reads/writes it). Max 4.",
    {
      address: { type: "number", description: "Data address to watch", required: true },
      size: { type: "integer", description: "1, 2, 4, or 8 bytes", required: true },
      on_read: { type: "boolean", description: "Trigger on read (default false)" },
      on_write: { type: "boolean", description: "Trigger on write (default true)" },
    },
    async (args) => rpc("debug.watchpoint_set", {
      address: args.address,
      size: args.size,
      on_read: args.on_read ?? false,
      on_write: args.on_write ?? true,
    }))

  addTool("ce_debug_watchpoint_clear", "Clear a hardware watchpoint.",
    { address: { type: "number", description: "Data address", required: true } },
    async (args) => rpc("debug.watchpoint_clear", { address: args.address }))

  addTool("ce_debug_single_step", "Single-step one instruction of the current thread (after a breakpoint/watchpoint).",
    { thread_id: { type: "integer", description: "Thread id from a debug event", required: true } },
    async (args) => rpc("debug.single_step", { thread_id: args.thread_id }))

  addTool("ce_debug_stack", "Unwind the call stack of a suspended thread (RBP chain) at a breakpoint/watchpoint; frames annotated with module+offset.",
    {
      thread_id: { type: "integer", description: "Thread id from a debug event", required: true },
      max_frames: { type: "integer", description: "Max frames to unwind (default 16)" },
    },
    async (args) => rpc("debug.stack", { thread_id: args.thread_id, max_frames: args.max_frames ?? 16 }))

  addTool("ce_debug_accessor", 'Accessor closure: at a breakpoint/watchpoint, report the instruction at RIP with module+offset+symbol and registers ("who is accessing this address").',
    { thread_id: { type: "integer", description: "Thread id from a debug event", required: true } },
    async (args) => rpc("debug.accessor", { thread_id: args.thread_id }))

  addTool("ce_thread_inject_dll", "Inject a DLL into a process: remote thread runs LoadLibraryW(path) in the target. Returns thread_id, completed, exit_code.",
    {
      pid: { type: "integer", description: "Process id", required: true },
      path: { type: "string", description: "Absolute DLL path (e.g. C:\\path\\hook.dll)", required: true },
      timeout_ms: { type: "integer", description: "Wait limit for the loader thread (default 10000)" },
    },
    async (args) => rpc("thread.inject_dll", { pid: args.pid, path: args.path, timeout_ms: args.timeout_ms ?? 10000 }))

  addTool("ce_thread_create_remote", "Execute raw x64 shellcode in a process via a remote thread (attack simulation / analysis hooks). Build the code with ce_asm; must end with ret. Returns thread_id, completed, exit_code.",
    {
      pid: { type: "integer", description: "Process id", required: true },
      code: { type: "array", items: { type: "integer" }, description: "Shellcode bytes as a decimal array (0-255); build the machine code with ce_asm first", required: true },
      arg: { type: "integer", description: "Value passed as the thread parameter (default 0)" },
      timeout_ms: { type: "integer", description: "Wait limit for the thread (default 10000)" },
    },
    async (args) => {
      return rpc("thread.create_remote", { pid: args.pid, code: bytesToB64(args.code), arg: args.arg ?? 0, timeout_ms: args.timeout_ms ?? 10000 })
    })

  addTool("ce_trainer_freeze", "Freeze a memory value: a background thread writes the given bytes to the address every interval_ms (trainer-style value lock).",
    {
      address: { type: "number", description: "Address to keep writing", required: true },
      bytes: { type: "array", items: { type: "integer" }, description: "Bytes to write back repeatedly (decimal 0-255)", required: true },
      interval_ms: { type: "integer", description: "Write interval in ms (default 16)" },
    },
    async (args) => rpc("trainer.freeze", { address: args.address, bytes: bytesToB64(args.bytes), interval_ms: args.interval_ms ?? 16 }))

  addTool("ce_trainer_unfreeze", "Stop a freeze job.",
    { freeze_id: { type: "integer", description: "freeze_id from ce_trainer_freeze", required: true } },
    async (args) => rpc("trainer.unfreeze", { freeze_id: args.freeze_id }))

  addTool("ce_trainer_list", "List active freeze jobs.", {},
    async () => rpc("trainer.list", {}))

  addTool("ce_patch_export", "Export all memory writes as a patch list (address, original bytes, new bytes) — a .CT-style JSON for replay/rollback.",
    {},
    async () => rpc("patch.export", {}))

  addTool("ce_hook_install", "Install an inline hook: jmp at target to your hook code (built with ce_asm), with a trampoline carrying the original bytes + jmp-back. Returns trampoline address.",
    {
      address: { type: "number", description: "Target code address", required: true },
      hook: { type: "array", items: { type: "integer" }, description: "Hook code bytes (decimal 0-255), must end with ret", required: true },
    },
    async (args) => rpc("hook.install", { address: args.address, hook: bytesToB64(args.hook) }))

  addTool("ce_hook_remove", "Remove an inline hook (restore original bytes from the trampoline).",
    { address: { type: "number", description: "Target code address", required: true } },
    async (args) => rpc("hook.remove", { address: args.address }))

  addTool("ce_hook_list", "List installed hooks.", {},
    async () => rpc("hook.list", {}))

  ctx.effect(() => () => {
    for (const d of disposers) { try { d() } catch (e) {} }
    if (handle !== undefined) { try { handle.terminate() } catch (e) {} }
  })
}
