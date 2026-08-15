//! `ce-serve` 库面：JSON-RPC 2.0 分发器 + 会话状态。
//!
//! bin（`main.rs`）提供 stdio 守护进程与 `--one-shot` 模式；
//! 库面供 `ce-mcp` 等上层复用同一套分发逻辑。

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use ce_core::api::{self, method, Response, ResponseBody};
use ce_core::scan::Scan;
use ce_core::{Address, PointerHop};
use ce_proc::{list_processes, open, Process};

/// 单次内存读取上限（防止意外的大块分配）。
pub const MAX_READ_SIZE: usize = 1024 * 1024;

/// 会话状态：当前目标进程 + 值/指针扫描会话 + 调试器 + 内存快照 + 结构体
/// + 符号解析 + 反汇编缓存 + 训练器（freeze）+ 补丁记录 + 内联钩子。
pub struct Session {
    process: Option<Box<dyn Process>>,
    scans: HashMap<u64, Scan>,
    pointer_scans: HashMap<u64, PointerScanSession>,
    debugger: Option<ce_proc::Debugger>,
    snapshots: HashMap<u64, MemorySnapshot>,
    structs: HashMap<String, ce_core::Structure>,
    #[cfg(target_os = "windows")]
    symbols: Option<ce_proc::pdb::SymbolResolver>,
    disasm_cache: HashMap<(Address, usize), Vec<ce_core::DisasmResult>>,
    freezes: HashMap<u64, FreezeJob>,
    writes: Vec<PatchRecord>,
    hooks: HashMap<Address, HookRecord>,
    next_scan_id: u64,
    next_snapshot_id: u64,
    next_freeze_id: u64,
}

/// 一次指针扫描会话（二次快照去噪用）。
#[derive(serde::Deserialize)]
struct PointerScanSession {
    target: Address,
    pointer_size: usize,
    chains: Vec<Vec<PointerHop>>,
}

/// 一次内存区域快照。
struct MemorySnapshot {
    address: Address,
    bytes: Vec<u8>,
}

/// 一次训练器 freeze 任务（后台线程周期性写回）。
struct FreezeJob {
    address: Address,
    bytes: Vec<u8>,
    interval_ms: u64,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// 一条内存补丁记录（memory.write 日志）。
struct PatchRecord {
    address: Address,
    original: Vec<u8>,
    new: Vec<u8>,
}

/// 一个内联钩子：目标地址的跳转补丁 + trampoline + 钩子代码洞。
struct HookRecord {
    trampoline: Address,
    hook_cave: Address,
    patch_len: usize,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Session {
            process: None,
            scans: HashMap::new(),
            pointer_scans: HashMap::new(),
            debugger: None,
            snapshots: HashMap::new(),
            structs: HashMap::new(),
            #[cfg(target_os = "windows")]
            symbols: None,
            disasm_cache: HashMap::new(),
            freezes: HashMap::new(),
            writes: Vec::new(),
            hooks: HashMap::new(),
            next_scan_id: 1,
            next_snapshot_id: 1,
            next_freeze_id: 1,
        }
    }

    /// 切换/释放目标进程时清理全部扫描会话。
    fn clear_process(&mut self) {
        self.process = None;
        self.scans.clear();
        self.pointer_scans.clear();
        self.snapshots.clear();
        self.disasm_cache.clear();
        self.hooks.clear();
        // 停止全部 freeze 线程。
        for (_, job) in self.freezes.drain() {
            job.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.writes.clear();
    }

    /// 目标位宽（32/64），供反汇编/汇编使用。
    pub fn bitness(&self) -> u32 {
        match &self.process {
            Some(p) if p.info().pointer_size == 4 => 32,
            _ => 64,
        }
    }
}

/// 解析紧凑一次性规范 `scan:<value_type>:<scan_type>:<value>`。
pub fn parse_compact_spec(spec: &str) -> (String, serde_json::Value) {
    let parts: Vec<&str> = spec.splitn(4, ':').collect();
    if parts.len() == 4 && parts[0] == "scan" {
        let value = parts[3]
            .parse::<i64>()
            .ok()
            .map(|n| serde_json::json!(n))
            .unwrap_or_else(|| serde_json::json!(parts[3]));
        (
            "scan.new".to_string(),
            serde_json::json!({
                "value_type": parts[1],
                "scan_type": parts[2],
                "value": value,
            }),
        )
    } else {
        (spec.to_string(), serde_json::Value::Null)
    }
}

/// 面向上层（MCP 等）的便捷入口：执行一个方法，返回结果值（而非 Response 包装）。
pub fn handle(
    session: &mut Session,
    method_name: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, (i64, String)> {
    match dispatch(session, 0, method_name, params) {
        Ok(resp) => match resp.body {
            ResponseBody::Result(v) => Ok(v),
            ResponseBody::Error { code, message } => Err((code, message)),
        },
        Err(e) => Err(e),
    }
}

pub type AppResult = Result<Response, (i64, String)>;

/// 取当前目标进程的不可变引用（借用 `session.process` 字段）。
fn proc_ref(session: &Session) -> Result<&dyn Process, (i64, String)> {
    session
        .process
        .as_deref()
        .ok_or((api::error_code::APPLICATION, "no process attached".to_string()))
}

fn debugger_ref(session: &Session) -> Result<&ce_proc::Debugger, (i64, String)> {
    session
        .debugger
        .as_ref()
        .ok_or((api::error_code::APPLICATION, "no debugger attached".to_string()))
}

fn parse<T: serde::de::DeserializeOwned>(params: serde_json::Value) -> Result<T, (i64, String)> {
    serde_json::from_value(params).map_err(|e| (api::error_code::INVALID_PARAMS, e.to_string()))
}

fn app(e: ce_proc::ProcessError) -> (i64, String) {
    (api::error_code::APPLICATION, e.to_string())
}

/// 分发一个 JSON-RPC 方法调用，返回完整响应。
pub fn dispatch(session: &mut Session, id: u64, method: &str, params: serde_json::Value) -> AppResult {
    match method {
        method::PROCESS_LIST => {
            let procs = list_processes().map_err(app)?;
            Ok(Response::ok(id, procs))
        }
        method::PROCESS_ATTACH => {
            let p: api::AttachParams = parse(params)?;
            let proc = open(p.pid).map_err(app)?;
            let info = proc.info();
            session.clear_process();
            session.process = Some(proc);
            Ok(Response::ok(id, info))
        }
        method::PROCESS_DETACH => {
            session.clear_process();
            Ok(Response::ok(id, serde_json::json!({})))
        }
        method::MEMORY_REGIONS => {
            let proc = proc_ref(session)?;
            let regions = proc.regions().map_err(app)?;
            Ok(Response::ok(id, regions))
        }
        method::MEMORY_READ => {
            let p: api::ReadParams = parse(params)?;
            if p.size > MAX_READ_SIZE {
                return Err((
                    api::error_code::INVALID_PARAMS,
                    format!("size too large (max {MAX_READ_SIZE})"),
                ));
            }
            let proc = proc_ref(session)?;
            let bytes = proc.read(p.address, p.size).map_err(app)?;
            Ok(Response::ok(
                id,
                serde_json::json!({ "bytes": STANDARD.encode(bytes) }),
            ))
        }
        method::MEMORY_WRITE => {
            let p: api::WriteParams = parse(params)?;
            let bytes = STANDARD
                .decode(&p.bytes)
                .map_err(|e| (api::error_code::INVALID_PARAMS, format!("bad base64: {e}")))?;
            let proc = proc_ref(session)?;
            // 记录补丁（先读原字节，供 patch.export 导出/回滚）。
            let original = proc.read(p.address, bytes.len()).unwrap_or_default();
            let written = proc.write(p.address, &bytes).map_err(app)?;
            session
                .writes
                .push(PatchRecord { address: p.address, original, new: bytes });
            Ok(Response::ok(id, serde_json::json!({ "written": written })))
        }
        method::MEMORY_SNAPSHOT => {
            let p: api::ReadParams = parse(params)?;
            if p.size > MAX_READ_SIZE {
                return Err((
                    api::error_code::INVALID_PARAMS,
                    format!("size too large (max {MAX_READ_SIZE})"),
                ));
            }
            let proc = proc_ref(session)?;
            let bytes = proc.read(p.address, p.size).map_err(app)?;
            let snapshot_id = session.next_snapshot_id;
            session.next_snapshot_id += 1;
            session.snapshots.insert(
                snapshot_id,
                MemorySnapshot {
                    address: p.address,
                    bytes,
                },
            );
            Ok(Response::ok(
                id,
                serde_json::json!({ "snapshot_id": snapshot_id, "size": p.size }),
            ))
        }
        method::MEMORY_DIFF => {
            let p: api::SnapshotIdParams = parse(params)?;
            let snap = session.snapshots.get(&p.snapshot_id).ok_or((
                api::error_code::APPLICATION,
                format!("unknown snapshot_id {}", p.snapshot_id),
            ))?;
            let proc = proc_ref(session)?;
            let current = proc.read(snap.address, snap.bytes.len()).map_err(app)?;

            let mut changes: Vec<serde_json::Value> = Vec::new();
            for (i, (cur, old)) in current.iter().zip(snap.bytes.iter()).enumerate() {
                if cur != old {
                    changes.push(serde_json::json!({
                        "offset": i,
                        "address": snap.address + i as u64,
                        "old": old,
                        "new": cur,
                    }));
                }
            }
            Ok(Response::ok(
                id,
                serde_json::json!({ "total": changes.len(), "changes": changes }),
            ))
        }
        method::SCAN_NEW => {
            let p: api::ScanNewParams = parse(params)?;
            let proc = proc_ref(session)?;
            let opts = ce_core::scan::ScanOpts {
                mask: p.mask,
                min: p.min,
                max: p.max,
                xor_key: p.xor_key,
            };
            let scan = Scan::first(proc, p.value_type, p.scan_type, &p.value, &opts);
            let scan_id = session.next_scan_id;
            session.next_scan_id += 1;
            let count = scan.len() as u64;
            session.scans.insert(scan_id, scan);
            Ok(Response::ok(
                id,
                serde_json::json!({ "scan_id": scan_id, "count": count }),
            ))
        }
        method::SCAN_NEXT => {
            let p: api::ScanNextParams = parse(params)?;
            // 先取扫描会话（可变借用 scans 字段），再取进程（字段级借用 process），互不冲突。
            let scan = session
                .scans
                .get_mut(&p.scan_id)
                .ok_or((api::error_code::APPLICATION, format!("unknown scan_id {}", p.scan_id)))?;
            let proc = match &session.process {
                Some(p) => p.as_ref(),
                None => return Err((api::error_code::APPLICATION, "no process attached".to_string())),
            };
            let opts = ce_core::scan::ScanOpts {
                mask: p.mask,
                min: p.min,
                max: p.max,
                xor_key: p.xor_key,
            };
            scan.next(proc, p.scan_type, &p.value, &opts);
            Ok(Response::ok(
                id,
                serde_json::json!({ "scan_id": p.scan_id, "count": scan.len() }),
            ))
        }
        method::SCAN_RESULTS => {
            let p: api::ScanResultsParams = parse(params)?;
            let scan = session.scans.get(&p.scan_id).ok_or((
                api::error_code::APPLICATION,
                format!("unknown scan_id {}", p.scan_id),
            ))?;
            let (total, results) = scan.results(p.offset, p.limit);
            Ok(Response::ok(
                id,
                serde_json::json!({ "total": total, "results": results }),
            ))
        }
        method::SCAN_CLOSE => {
            let p: api::ScanIdParams = parse(params)?;
            session.scans.remove(&p.scan_id).ok_or((
                api::error_code::APPLICATION,
                format!("unknown scan_id {}", p.scan_id),
            ))?;
            Ok(Response::ok(id, serde_json::json!({})))
        }
        // ---- M2 ----
        method::MEMORY_ALLOC => {
            let p: api::AllocParams = parse(params)?;
            let proc = proc_ref(session)?;
            let addr = proc.alloc(p.size).map_err(app)?;
            Ok(Response::ok(id, serde_json::json!({ "address": addr })))
        }
        method::DISASM => {
            let p: api::DisasmParams = parse(params)?;
            if p.length > MAX_READ_SIZE {
                return Err((
                    api::error_code::INVALID_PARAMS,
                    format!("length too large (max {MAX_READ_SIZE})"),
                ));
            }
            // 反汇编缓存：同一 (address, length) 不重复解码。
            if let Some(cached) = session.disasm_cache.get(&(p.address, p.length)) {
                return Ok(Response::ok(id, cached));
            }
            let proc = proc_ref(session)?;
            let bytes = proc.read(p.address, p.length).map_err(app)?;
            let bitness = session.bitness();
            let results = ce_core::disasm::decode(&bytes, p.address, bitness);
            if session.disasm_cache.len() > 256 {
                session.disasm_cache.clear();
            }
            session
                .disasm_cache
                .insert((p.address, p.length), results.clone());
            Ok(Response::ok(id, results))
        }
        method::ASM => {
            let p: api::AsmParams = parse(params)?;
            let bitness = session.bitness();
            let bytes = ce_core::asm::assemble(&p.code, bitness)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(id, serde_json::json!({ "bytes": bytes })))
        }
        method::SYMBOLS_LIST => {
            let p: api::SymbolsListParams = parse(params)?;
            let proc = proc_ref(session)?;
            let modules = proc.modules().map_err(app)?;
            let mut out: Vec<ce_core::Symbol> = Vec::new();
            for m in &modules {
                if let Some(filter) = &p.module {
                    if !m.name.eq_ignore_ascii_case(filter) && !m.path.eq_ignore_ascii_case(filter) {
                        continue;
                    }
                }
                let Ok(bytes) = std::fs::read(&m.path) else { continue };
                for (name, rva) in ce_core::symbols::parse_exports(&bytes) {
                    out.push(ce_core::Symbol {
                        name,
                        address: m.base + rva as u64,
                        module: m.name.clone(),
                    });
                }
            }
            Ok(Response::ok(id, out))
        }
        method::SYMBOLS_RESOLVE => {
            let p: api::SymbolsResolveParams = parse(params)?;
            let proc = proc_ref(session)?;
            let modules = proc.modules().map_err(app)?;
            for m in &modules {
                let Ok(bytes) = std::fs::read(&m.path) else { continue };
                for (name, rva) in ce_core::symbols::parse_exports(&bytes) {
                    if name.eq_ignore_ascii_case(&p.name) {
                        return Ok(Response::ok(
                            id,
                            serde_json::json!({ "address": m.base + rva as u64, "module": m.name }),
                        ));
                    }
                }
            }
            Err((
                api::error_code::APPLICATION,
                format!("symbol not found: {}", p.name),
            ))
        }
        method::POINTER_SCAN => {
            let p: api::PointerScanParams = parse(params)?;
            let proc = proc_ref(session)?;
            let chains = ce_core::scan::pointer::scan(
                proc,
                p.address,
                p.max_offset,
                p.max_depth,
                p.pointer_size,
                2000,
            );
            let modules = proc.modules().map_err(app)?;
            let out = chains_json(&chains, &modules);
            Ok(Response::ok(
                id,
                serde_json::json!({ "chains": out, "count": out.len() }),
            ))
        }
        method::POINTER_SCAN_START => {
            let p: api::PointerScanParams = parse(params)?;
            let proc = proc_ref(session)?;
            let chains = ce_core::scan::pointer::scan(
                proc,
                p.address,
                p.max_offset,
                p.max_depth,
                p.pointer_size,
                2000,
            );
            let scan_id = session.next_scan_id;
            session.next_scan_id += 1;
            let count = chains.len() as u64;
            session.pointer_scans.insert(
                scan_id,
                PointerScanSession {
                    target: p.address,
                    pointer_size: p.pointer_size,
                    chains,
                },
            );
            Ok(Response::ok(
                id,
                serde_json::json!({ "scan_id": scan_id, "count": count }),
            ))
        }
        method::POINTER_RESCAN => {
            let p: api::ScanIdParams = parse(params)?;
            let ps = session
                .pointer_scans
                .get_mut(&p.scan_id)
                .ok_or((
                    api::error_code::APPLICATION,
                    format!("unknown pointer scan_id {}", p.scan_id),
                ))?;
            let target = ps.target;
            let ptr_size = ps.pointer_size;
            let proc = match &session.process {
                Some(p) => p.as_ref(),
                None => {
                    return Err((
                        api::error_code::APPLICATION,
                        "no process attached".to_string(),
                    ))
                }
            };
            ps.chains
                .retain(|chain| ce_core::scan::pointer::chain_stable(proc, chain, target, ptr_size));
            let count = ps.chains.len() as u64;
            Ok(Response::ok(
                id,
                serde_json::json!({ "scan_id": p.scan_id, "count": count }),
            ))
        }
        method::POINTER_RESULTS => {
            let p: api::ScanResultsParams = parse(params)?;
            let proc = proc_ref(session)?;
            let modules = proc.modules().map_err(app)?;
            let ps = session.pointer_scans.get(&p.scan_id).ok_or((
                api::error_code::APPLICATION,
                format!("unknown pointer scan_id {}", p.scan_id),
            ))?;
            let total = ps.chains.len() as u64;
            let slice: Vec<Vec<PointerHop>> =
                ps.chains.iter().skip(p.offset).take(p.limit).cloned().collect();
            let out = chains_json(&slice, &modules);
            Ok(Response::ok(
                id,
                serde_json::json!({ "total": total, "chains": out }),
            ))
        }
        method::POINTER_CLOSE => {
            let p: api::ScanIdParams = parse(params)?;
            session.pointer_scans.remove(&p.scan_id).ok_or((
                api::error_code::APPLICATION,
                format!("unknown pointer scan_id {}", p.scan_id),
            ))?;
            Ok(Response::ok(id, serde_json::json!({})))
        }
        method::DEBUG_ATTACH => {
            let p: api::DebugAttachParams = parse(params)?;
            let dbg = ce_proc::Debugger::attach(p.pid)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            session.debugger = Some(dbg);
            Ok(Response::ok(
                id,
                serde_json::json!({ "attached": true, "pid": p.pid }),
            ))
        }
        method::DEBUG_DETACH => {
            session.debugger = None;
            Ok(Response::ok(id, serde_json::json!({})))
        }
        method::DEBUG_BREAKPOINT_SET => {
            let p: api::BreakpointParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            dbg.set_breakpoint(p.address)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(
                id,
                serde_json::json!({ "set": true, "address": p.address }),
            ))
        }
        method::DEBUG_BREAKPOINT_CLEAR => {
            let p: api::BreakpointParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            dbg.clear_breakpoint(p.address)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(id, serde_json::json!({ "cleared": true })))
        }
        method::DEBUG_WAIT => {
            let p: api::DebugWaitParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            match dbg.wait(p.timeout_ms) {
                Some(ev) => Ok(Response::ok(id, ev)),
                None => Ok(Response::ok(id, serde_json::Value::Null)),
            }
        }
        method::DEBUG_CONTINUE => {
            let dbg = debugger_ref(session)?;
            dbg.continue_execution();
            Ok(Response::ok(id, serde_json::json!({ "continued": true })))
        }
        method::DEBUG_REGISTERS => {
            let p: api::DebugRegistersParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            let regs = dbg
                .registers(p.thread_id)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(id, regs))
        }
        method::DEBUG_REGISTERS_SET => {
            let p: api::DebugRegistersSetParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            dbg.set_registers(p.thread_id, &p.registers)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(id, serde_json::json!({ "set": true })))
        }
        method::DEBUG_WATCHPOINT_SET => {
            let p: api::WatchpointSetParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            dbg.set_watchpoint(p.address, p.size, p.on_read, p.on_write)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(
                id,
                serde_json::json!({ "set": true, "address": p.address }),
            ))
        }
        method::DEBUG_WATCHPOINT_CLEAR => {
            let p: api::BreakpointParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            dbg.clear_watchpoint(p.address)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(id, serde_json::json!({ "cleared": true })))
        }
        method::DEBUG_SINGLE_STEP => {
            let p: api::DebugRegistersParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            dbg.single_step(p.thread_id)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            Ok(Response::ok(id, serde_json::json!({ "stepped": true })))
        }
        method::STRUCT_DEFINE => {
            let p: api::StructDefineParams = parse(params)?;
            if p.name.trim().is_empty() {
                return Err((api::error_code::INVALID_PARAMS, "empty struct name".to_string()));
            }
            if p.fields.is_empty() {
                return Err((api::error_code::INVALID_PARAMS, "empty field list".to_string()));
            }
            let s = ce_core::Structure {
                name: p.name.clone(),
                fields: p.fields,
            };
            session.structs.insert(p.name, s);
            Ok(Response::ok(id, serde_json::json!({ "defined": true })))
        }
        method::STRUCT_READ => {
            let p: api::StructReadParams = parse(params)?;
            let s = session.structs.get(&p.name).ok_or((
                api::error_code::APPLICATION,
                format!("unknown struct '{}'", p.name),
            ))?;
            let proc = proc_ref(session)?;
            let mut fields = Vec::new();
            for f in &s.fields {
                let fv = read_struct_field(proc, p.address, f)
                    .map_err(|e| (api::error_code::APPLICATION, e))?;
                fields.push(fv);
            }
            Ok(Response::ok(
                id,
                serde_json::json!({ "name": p.name, "address": p.address, "fields": fields }),
            ))
        }
        method::STRUCT_LIST => {
            let names: Vec<&String> = session.structs.keys().collect();
            Ok(Response::ok(id, serde_json::json!(names)))
        }
        method::STRUCT_DELETE => {
            let p: api::StructNameParams = parse(params)?;
            session.structs.remove(&p.name).ok_or((
                api::error_code::APPLICATION,
                format!("unknown struct '{}'", p.name),
            ))?;
            Ok(Response::ok(id, serde_json::json!({ "deleted": true })))
        }
        // ---- 防护：反作弊感知（Windows 专属；Linux 无此能力） ----
        #[cfg(target_os = "windows")]
        method::PROTECT_STATUS => {
            let detected = ce_proc::detect_anti_cheats();
            let kernel = detected.iter().any(|a| a.kernel);
            Ok(Response::ok(
                id,
                serde_json::json!({
                    "detected": detected,
                    "protected": !detected.is_empty(),
                    "kernel_protection": kernel,
                }),
            ))
        }
        #[cfg(not(target_os = "windows"))]
        method::PROTECT_STATUS => {
            Ok(Response::ok(
                id,
                serde_json::json!({
                    "detected": [],
                    "protected": false,
                    "kernel_protection": false,
                    "note": "anti-cheat detection is Windows-only",
                }),
            ))
        }
        // ---- 分析：远程线程注入（Windows 专属） ----
        #[cfg(target_os = "windows")]
        method::THREAD_INJECT_DLL => {
            let p: api::InjectDllParams = parse(params)?;
            let timeout = p.timeout_ms.unwrap_or(10_000);
            let r = ce_proc::inject_dll(p.pid, &p.path, timeout).map_err(app)?;
            Ok(Response::ok(id, r))
        }
        #[cfg(not(target_os = "windows"))]
        method::THREAD_INJECT_DLL => Err((
            api::error_code::APPLICATION,
            "thread.inject_dll is Windows-only".to_string(),
        )),
        #[cfg(target_os = "windows")]
        method::THREAD_CREATE_REMOTE => {
            let p: api::CreateRemoteParams = parse(params)?;
            let code = STANDARD.decode(&p.code).map_err(|e| {
                (api::error_code::INVALID_PARAMS, format!("bad base64: {e}"))
            })?;
            let timeout = p.timeout_ms.unwrap_or(10_000);
            let r = ce_proc::create_remote(p.pid, &code, p.arg.unwrap_or(0), timeout).map_err(app)?;
            Ok(Response::ok(id, r))
        }
        #[cfg(not(target_os = "windows"))]
        method::THREAD_CREATE_REMOTE => Err((
            api::error_code::APPLICATION,
            "thread.create_remote is Windows-only".to_string(),
        )),
        // ---- 分析：调用栈回溯 ----
        method::DEBUG_STACK => {
            let p: api::StackParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            let frames = dbg
                .stack(p.thread_id, p.max_frames.unwrap_or(16))
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            let modules = proc_ref(session)?.modules().map_err(app)?;
            let out: Vec<serde_json::Value> = frames
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let mut v = serde_json::json!({
                        "frame": i,
                        "rip": f.rip,
                        "rbp": f.rbp,
                        "rsp": f.rsp,
                    });
                    if let Some(m) = modules
                        .iter()
                        .find(|m| f.rip >= m.base && f.rip < m.base + m.size)
                    {
                        v["module"] = serde_json::json!(m.name);
                        v["offset"] = serde_json::json!(format!("0x{:x}", f.rip - m.base));
                    }
                    v
                })
                .collect();
            Ok(Response::ok(
                id,
                serde_json::json!({ "count": out.len(), "frames": out }),
            ))
        }
        // ---- 指针链分析 ----
        method::POINTER_ANALYZE => {
            let p: api::ScanIdParams = parse(params)?;
            let ps = session.pointer_scans.get(&p.scan_id).ok_or((
                api::error_code::APPLICATION,
                format!("unknown pointer scan_id {}", p.scan_id),
            ))?;
            let analysis = ce_core::scan::pointer::analyze(&ps.chains);
            Ok(Response::ok(id, analysis))
        }
        method::POINTER_STRUCT_SPAWN => {
            let p: api::ScanIdParams = parse(params)?;
            let ps = session.pointer_scans.get(&p.scan_id).ok_or((
                api::error_code::APPLICATION,
                format!("unknown pointer scan_id {}", p.scan_id),
            ))?;
            let fields = ce_core::scan::pointer::struct_spawn(&ps.chains);
            Ok(Response::ok(
                id,
                serde_json::json!({ "name": "spawned", "fields": fields, "count": fields.len() }),
            ))
        }
        // ---- 反汇编工具链 ----
        method::DISASM_XREFS => {
            let p: api::DisasmXrefsParams = parse(params)?;
            let proc = proc_ref(session)?;
            let bitness = session.bitness();
            let xrefs = ce_core::disasm::xrefs(proc, p.address, bitness, p.limit.unwrap_or(100));
            // 标注模块。
            let modules = proc.modules().map_err(app)?;
            let out: Vec<serde_json::Value> = xrefs
                .iter()
                .map(|d| {
                    let mut v = serde_json::json!({
                        "address": d.address,
                        "bytes": d.bytes,
                        "text": d.text,
                    });
                    if let Some(m) = modules
                        .iter()
                        .find(|m| d.address >= m.base && d.address < m.base + m.size)
                    {
                        v["module"] = serde_json::json!(m.name);
                        v["offset"] = serde_json::json!(format!("0x{:x}", d.address - m.base));
                    }
                    v
                })
                .collect();
            Ok(Response::ok(id, serde_json::json!({ "count": out.len(), "xrefs": out })))
        }
        method::DISASM_FUNCTION => {
            let p: api::DisasmFunctionParams = parse(params)?;
            let proc = proc_ref(session)?;
            let bitness = session.bitness();
            let info = ce_core::disasm::function_boundary(
                proc,
                p.address,
                bitness,
                p.max_back.unwrap_or(256),
                p.max_len.unwrap_or(4096),
            );
            match info {
                Some(info) => Ok(Response::ok(id, info)),
                None => Err((
                    api::error_code::APPLICATION,
                    "cannot read code around address".to_string(),
                )),
            }
        }
        // ---- PDB 符号解析 ----
        #[cfg(target_os = "windows")]
        method::SYMBOLS_PDB_RESOLVE => {
            let p: api::PdbResolveParams = parse(params)?;
            // 懒初始化符号引擎。
            if session.symbols.is_none() {
                let handle = proc_ref(session)?
                    .raw_handle()
                    .ok_or((api::error_code::APPLICATION, "no process handle".to_string()))?;
                let resolver = ce_proc::pdb::SymbolResolver::init(handle, "")
                    .map_err(|e| (api::error_code::APPLICATION, e))?;
                session.symbols = Some(resolver);
            }
            let resolver = session
                .symbols
                .as_ref()
                .ok_or((api::error_code::APPLICATION, "symbol engine unavailable".to_string()))?;
            match resolver.resolve(p.address) {
                Some(name) => Ok(Response::ok(
                    id,
                    serde_json::json!({ "address": p.address, "name": name }),
                )),
                None => Ok(Response::ok(
                    id,
                    serde_json::json!({ "address": p.address, "name": null }),
                )),
            }
        }
        #[cfg(not(target_os = "windows"))]
        method::SYMBOLS_PDB_RESOLVE => Err((
            api::error_code::APPLICATION,
            "symbols.pdb_resolve is Windows-only".to_string(),
        )),
        // ---- 会话持久化 ----
        method::SESSION_SAVE => {
            let data = serde_json::json!({
                "structs": session.structs,
                "pointer_scans": session.pointer_scans.iter().map(|(id, ps)| serde_json::json!({
                    "scan_id": id,
                    "target": ps.target,
                    "pointer_size": ps.pointer_size,
                    "chains": ps.chains,
                })).collect::<Vec<_>>(),
                "patches": session.writes.iter().map(|w| serde_json::json!({
                    "address": w.address,
                    "original": STANDARD.encode(&w.original),
                    "new": STANDARD.encode(&w.new),
                })).collect::<Vec<_>>(),
                "freezes": session.freezes.iter().map(|(id, f)| serde_json::json!({
                    "freeze_id": id,
                    "address": f.address,
                    "bytes": STANDARD.encode(&f.bytes),
                    "interval_ms": f.interval_ms,
                })).collect::<Vec<_>>(),
                "hooks": session.hooks.iter().map(|(addr, h)| serde_json::json!({
                    "address": addr,
                    "trampoline": h.trampoline,
                    "hook_cave": h.hook_cave,
                    "patch_len": h.patch_len,
                })).collect::<Vec<_>>(),
            });
            let json = serde_json::to_string(&data)
                .map_err(|e| (api::error_code::INTERNAL, e.to_string()))?;
            Ok(Response::ok(
                id,
                serde_json::json!({ "data": STANDARD.encode(json.as_bytes()) }),
            ))
        }
        method::SESSION_LOAD => {
            let p: api::SessionLoadParams = parse(params)?;
            let json = STANDARD
                .decode(&p.data)
                .map_err(|e| (api::error_code::INVALID_PARAMS, format!("bad base64: {e}")))?;
            let data: serde_json::Value = serde_json::from_slice(&json)
                .map_err(|e| (api::error_code::INVALID_PARAMS, format!("bad session json: {e}")))?;
            // 结构体。
            if let Some(structs) = data.get("structs").and_then(|v| v.as_object()) {
                session.structs.clear();
                for (name, v) in structs {
                    if let Ok(s) = serde_json::from_value::<ce_core::Structure>(v.clone()) {
                        session.structs.insert(name.clone(), s);
                    }
                }
            }
            // 指针链。
            if let Some(list) = data.get("pointer_scans").and_then(|v| v.as_array()) {
                for v in list {
                    let id = v.get("scan_id").and_then(|x| x.as_u64()).unwrap_or(0);
                    let Ok(ps) = serde_json::from_value::<PointerScanSession>(v.clone()) else {
                        continue;
                    };
                    session.pointer_scans.insert(id, ps);
                }
            }
            Ok(Response::ok(
                id,
                serde_json::json!({ "loaded": true }),
            ))
        }
        // ---- 访问者闭环 ----
        method::DEBUG_ACCESSOR => {
            let p: api::DebugRegistersParams = parse(params)?;
            let dbg = debugger_ref(session)?;
            let regs = dbg
                .registers(p.thread_id)
                .map_err(|e| (api::error_code::APPLICATION, e))?;
            let proc = proc_ref(session)?;
            let modules = proc.modules().map_err(app)?;
            let bitness = session.bitness();
            // 反汇编触发指令（读取 RIP 处最多 15 字节）。
            let code = proc.read(regs.rip, 15).unwrap_or_default();
            let instrs = ce_core::disasm::decode(&code, regs.rip, bitness);
            let instruction = instrs.first().map(|d| serde_json::json!({
                "address": d.address,
                "bytes": d.bytes,
                "text": d.text,
            }));
            let mut out = serde_json::json!({
                "rip": regs.rip,
                "registers": regs,
                "instruction": instruction,
            });
            if let Some(m) = modules
                .iter()
                .find(|m| regs.rip >= m.base && regs.rip < m.base + m.size)
            {
                out["module"] = serde_json::json!(m.name);
                out["offset"] = serde_json::json!(format!("0x{:x}", regs.rip - m.base));
            }
            #[cfg(target_os = "windows")]
            if let Some(resolver) = &session.symbols {
                if let Some(name) = resolver.resolve(regs.rip) {
                    out["symbol"] = serde_json::json!(name);
                }
            }
            Ok(Response::ok(id, out))
        }
        // ---- 模块 AOB 签名扫描 ----
        method::MODULE_AOB_SCAN => {
            let p: api::ModuleAobScanParams = parse(params)?;
            let (pattern, mask) = ce_core::scan::parse_aob(&p.pattern)
                .map_err(|e| (api::error_code::INVALID_PARAMS, e))?;
            let proc = proc_ref(session)?;
            let hits = match &p.module {
                Some(filter) => {
                    // 限定模块范围搜索。
                    let modules = proc.modules().map_err(app)?;
                    let m = modules
                        .iter()
                        .find(|m| {
                            m.name.eq_ignore_ascii_case(filter)
                                || m.path.eq_ignore_ascii_case(filter)
                        })
                        .ok_or((
                            api::error_code::APPLICATION,
                            format!("module not found: {filter}"),
                        ))?;
                    search_range(proc, m.base, m.size, &pattern, &mask, 1000)
                }
                None => ce_core::scan::aob_search(proc, &pattern, &mask, 1000),
            };
            Ok(Response::ok(
                id,
                serde_json::json!({ "count": hits.len(), "hits": hits }),
            ))
        }
        // ---- 训练器：freeze ----
        method::TRAINER_FREEZE => {
            let p: api::TrainerFreezeParams = parse(params)?;
            let bytes = STANDARD
                .decode(&p.bytes)
                .map_err(|e| (api::error_code::INVALID_PARAMS, format!("bad base64: {e}")))?;
            let interval = p.interval_ms.unwrap_or(16).max(1);
            let (pid, addr) = {
                let proc = proc_ref(session)?;
                (proc.pid(), p.address)
            };
            let freeze_id = session.next_freeze_id;
            session.next_freeze_id += 1;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop2 = stop.clone();
            let b2 = bytes.clone();
            let thread = std::thread::spawn(move || {
                let handle = ce_proc::open(pid).ok();
                while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(h) = &handle {
                        let _ = h.write(addr, &b2);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(interval));
                }
            });
            session.freezes.insert(
                freeze_id,
                FreezeJob {
                    address: addr,
                    bytes,
                    interval_ms: interval,
                    stop,
                    thread: Some(thread),
                },
            );
            Ok(Response::ok(
                id,
                serde_json::json!({ "freeze_id": freeze_id, "address": addr }),
            ))
        }
        method::TRAINER_UNFREEZE => {
            let p: api::TrainerIdParams = parse(params)?;
            if let Some(job) = session.freezes.remove(&p.freeze_id) {
                job.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                if let Some(t) = job.thread {
                    let _ = t.join();
                }
            }
            Ok(Response::ok(id, serde_json::json!({ "unfrozen": true })))
        }
        method::TRAINER_LIST => {
            let list: Vec<serde_json::Value> = session
                .freezes
                .iter()
                .map(|(id, f)| {
                    serde_json::json!({
                        "freeze_id": id,
                        "address": f.address,
                        "size": f.bytes.len(),
                        "interval_ms": f.interval_ms,
                    })
                })
                .collect();
            Ok(Response::ok(id, serde_json::json!({ "freezes": list })))
        }
        // ---- 补丁导出 ----
        method::PATCH_EXPORT => {
            let patches: Vec<serde_json::Value> = session
                .writes
                .iter()
                .map(|w| {
                    serde_json::json!({
                        "address": w.address,
                        "original": STANDARD.encode(&w.original),
                        "bytes": STANDARD.encode(&w.new),
                    })
                })
                .collect();
            Ok(Response::ok(
                id,
                serde_json::json!({
                    "name": "ce-lite-patches",
                    "patch_count": patches.len(),
                    "patches": patches,
                }),
            ))
        }
        // ---- 内联钩子 ----
        method::HOOK_INSTALL => {
            let p: api::HookInstallParams = parse(params)?;
            let bitness = session.bitness();
            let hook_code = STANDARD
                .decode(&p.hook)
                .map_err(|e| (api::error_code::INVALID_PARAMS, format!("bad base64: {e}")))?;
            // 在作用域内完成所有进程操作，之后才可变借用 session.hooks。
            let (trampoline, hook_cave, patch_len) = {
                let proc = proc_ref(session)?;
                // 1) 解码目标处指令，确定需覆盖的字节数（>=5）。
                let code = proc.read(p.address, 64).map_err(app)?;
                let instrs = ce_core::disasm::decode(&code, p.address, bitness);
                let mut patch_len = 0usize;
                for ins in &instrs {
                    patch_len += ins.bytes.len();
                    if patch_len >= 5 {
                        break;
                    }
                }
                if patch_len < 5 {
                    return Err((
                        api::error_code::APPLICATION,
                        "cannot find 5 bytes of instructions at target".to_string(),
                    ));
                }
                let original = proc.read(p.address, patch_len).map_err(app)?;
                // 2) 分配 trampoline（原字节 + jmp 回 target+patch_len）与 hook 洞。
                let trampoline = proc.alloc(original.len() + 5).map_err(app)?;
                let mut tramp = original.clone();
                tramp.extend_from_slice(&rel_jmp(
                    trampoline + original.len() as u64,
                    p.address + patch_len as u64,
                ));
                proc.write(trampoline, &tramp).map_err(app)?;
                let hook_cave = proc.alloc(hook_code.len()).map_err(app)?;
                proc.write(hook_cave, &hook_code).map_err(app)?;
                // 3) 目标处写 jmp hook_cave。
                let jmp = rel_jmp(p.address, hook_cave);
                proc.write(p.address, &jmp).map_err(app)?;
                (trampoline, hook_cave, patch_len)
            };
            session.hooks.insert(
                p.address,
                HookRecord {
                    trampoline,
                    hook_cave,
                    patch_len,
                },
            );
            Ok(Response::ok(
                id,
                serde_json::json!({
                    "installed": true,
                    "address": p.address,
                    "trampoline": trampoline,
                    "hook_cave": hook_cave,
                    "patch_len": patch_len,
                }),
            ))
        }
        method::HOOK_REMOVE => {
            let p: api::BreakpointParams = parse(params)?;
            let hook = session
                .hooks
                .remove(&p.address)
                .ok_or((api::error_code::APPLICATION, "hook not installed".to_string()))?;
            // 从 trampoline 读回原字节并还原目标处。
            let tramp = {
                let proc = proc_ref(session)?;
                proc.read(hook.trampoline, hook.patch_len).map_err(app)?
            };
            let proc = proc_ref(session)?;
            proc.write(p.address, &tramp).map_err(app)?;
            Ok(Response::ok(
                id,
                serde_json::json!({ "removed": true, "address": p.address }),
            ))
        }
        method::HOOK_LIST => {
            let list: Vec<serde_json::Value> = session
                .hooks
                .iter()
                .map(|(addr, h)| {
                    serde_json::json!({
                        "address": addr,
                        "trampoline": h.trampoline,
                        "hook_cave": h.hook_cave,
                        "patch_len": h.patch_len,
                    })
                })
                .collect();
            Ok(Response::ok(id, serde_json::json!({ "hooks": list })))
        }
        other => Err((
            api::error_code::METHOD_NOT_FOUND,
            format!("method not found: {other}"),
        )),
    }
}

/// 把指针链序列化为 JSON，并对落在模块内的指针标注 `module+offset`。
fn chains_json(chains: &[Vec<PointerHop>], modules: &[ce_core::ModuleInfo]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for chain in chains {
        let mut c = Vec::new();
        for hop in chain {
            let mut node = serde_json::json!({
                "pointer_address": hop.pointer_address,
                "offset": hop.offset,
            });
            if let Some(m) = modules
                .iter()
                .find(|m| hop.pointer_address >= m.base && hop.pointer_address < m.base + m.size)
            {
                node["static"] = serde_json::json!(format!(
                    "{}+0x{:x}",
                    m.name,
                    hop.pointer_address - m.base
                ));
            }
            c.push(node);
        }
        out.push(serde_json::json!(c));
    }
    out
}

/// 构造 `E9 rel32` 相对跳转（from → to）。
fn rel_jmp(from: Address, to: Address) -> Vec<u8> {
    let mut code = Vec::with_capacity(5);
    code.push(0xE9);
    let rel = to.wrapping_sub(from.wrapping_add(5)) as i64 as i32;
    code.extend_from_slice(&rel.to_le_bytes());
    code
}

/// 在指定范围内搜索带掩码的 AOB 模式（分块读取防止大区域一次性分配）。
fn search_range(
    proc: &dyn Process,
    base: Address,
    size: u64,
    pattern: &[u8],
    mask: &[u8],
    limit: usize,
) -> Vec<Address> {
    let mut out = Vec::new();
    let chunk = 1024 * 1024usize;
    let overlap = pattern.len().saturating_sub(1);
    let total = size as usize;
    let mut off = 0usize;
    while off < total {
        let want = (total - off).min(chunk + overlap);
        let buf = proc.read(base + off as u64, want).unwrap_or_default();
        if buf.is_empty() {
            off += chunk;
            continue;
        }
        let search_len = buf.len().saturating_sub(overlap);
        for i in 0..search_len {
            if ce_core::scan::value::equals_masked(&buf[i..], pattern, mask) {
                out.push(base + off as u64 + i as u64);
                if out.len() >= limit {
                    return out;
                }
            }
        }
        off += chunk;
    }
    out
}

/// 读取结构体单个字段的值（按字段类型解释内存字节）。
fn read_struct_field(
    proc: &dyn Process,
    base: Address,
    field: &ce_core::StructField,
) -> Result<ce_core::StructFieldValue, String> {
    let addr = base + field.offset as u64;
    let value = match field.value_type {
        ce_core::ValueType::String => {
            let n = field.size.unwrap_or(256) as usize;
            let bytes = proc.read(addr, n).map_err(|e| e.to_string())?;
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            ce_core::Value::Str(String::from_utf8_lossy(&bytes[..end]).to_string())
        }
        ce_core::ValueType::Bytes | ce_core::ValueType::Binary => {
            let n = field.size.unwrap_or(16) as usize;
            let bytes = proc.read(addr, n).map_err(|e| e.to_string())?;
            ce_core::Value::Bytes(bytes)
        }
        vt => {
            let n = vt.size().unwrap_or(8);
            let bytes = proc.read(addr, n).map_err(|e| e.to_string())?;
            ce_core::scan::value::from_bytes(&bytes, vt).unwrap_or(ce_core::Value::None)
        }
    };
    Ok(ce_core::StructFieldValue {
        name: field.name.clone(),
        offset: field.offset,
        value_type: field.value_type,
        value,
    })
}
