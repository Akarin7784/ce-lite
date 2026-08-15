//! `ce-serve` — JSON-RPC 2.0 over stdio 守护进程。
//!
//! 从 stdin 逐行读取请求，向 stdout 逐行写回响应（newline-delimited JSON）。
//! 这是 AI 代理（如 DeepSeek Harness 插件经 `subprocess`）驱动的入口。

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use ce_core::api::{self, method, Response};
use ce_core::scan::Scan;
use ce_core::{Address, PointerHop};
use ce_proc::{list_processes, open, Process};

/// 单次内存读取上限（防止意外的大块分配）。
const MAX_READ_SIZE: usize = 1024 * 1024;

/// 会话状态：当前目标进程 + 值/指针扫描会话 + 调试器 + 内存快照 + 结构体。
struct Session {
    process: Option<Box<dyn Process>>,
    scans: HashMap<u64, Scan>,
    pointer_scans: HashMap<u64, PointerScanSession>,
    debugger: Option<ce_proc::debug::Debugger>,
    snapshots: HashMap<u64, MemorySnapshot>,
    structs: HashMap<String, ce_core::Structure>,
    next_scan_id: u64,
    next_snapshot_id: u64,
}

/// 一次指针扫描会话（二次快照去噪用）。
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

impl Session {
    fn new() -> Self {
        Session {
            process: None,
            scans: HashMap::new(),
            pointer_scans: HashMap::new(),
            debugger: None,
            snapshots: HashMap::new(),
            structs: HashMap::new(),
            next_scan_id: 1,
            next_snapshot_id: 1,
        }
    }

    /// 切换/释放目标进程时清理全部扫描会话。
    fn clear_process(&mut self) {
        self.process = None;
        self.scans.clear();
        self.pointer_scans.clear();
        self.snapshots.clear();
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut session = Session::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let resp = match serde_json::from_str::<api::Request>(&line) {
            Ok(req) => {
                let id = req.id;
                match dispatch(&mut session, id, &req.method, req.params) {
                    Ok(r) => r,
                    Err((code, msg)) => Response::err(id, code, msg),
                }
            }
            Err(e) => Response::err(0, api::error_code::PARSE_ERROR, format!("parse error: {e}")),
        };

        writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
        stdout.flush()?;
    }
    Ok(())
}

type AppResult = Result<Response, (i64, String)>;

/// 取当前目标进程的不可变引用（借用 `session.process` 字段）。
fn proc_ref(session: &Session) -> Result<&dyn Process, (i64, String)> {
    session
        .process
        .as_deref()
        .ok_or((api::error_code::APPLICATION, "no process attached".to_string()))
}

fn debugger_ref(session: &Session) -> Result<&ce_proc::debug::Debugger, (i64, String)> {
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

fn dispatch(session: &mut Session, id: u64, method: &str, params: serde_json::Value) -> AppResult {
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
            let written = proc.write(p.address, &bytes).map_err(app)?;
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
            let scan = Scan::first(proc, p.value_type, p.scan_type, &p.value);
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
            scan.next(proc, p.scan_type, &p.value);
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
            let proc = proc_ref(session)?;
            let bytes = proc.read(p.address, p.length).map_err(app)?;
            // M2：目标位宽默认 64，后续按目标 PE 判定。
            let results = ce_core::disasm::decode(&bytes, p.address, 64);
            Ok(Response::ok(id, results))
        }
        method::ASM => {
            let p: api::AsmParams = parse(params)?;
            // M2：目标位宽默认 64，后续按目标 PE 判定。
            let bytes = ce_core::asm::assemble(&p.code, 64)
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
            let dbg = ce_proc::debug::Debugger::attach(p.pid)
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
        // ---- 防护：反作弊感知 ----
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
        // ---- 分析：远程线程注入 ----
        method::THREAD_INJECT_DLL => {
            let p: api::InjectDllParams = parse(params)?;
            let timeout = p.timeout_ms.unwrap_or(10_000);
            let r = ce_proc::inject_dll(p.pid, &p.path, timeout).map_err(app)?;
            Ok(Response::ok(id, r))
        }
        method::THREAD_CREATE_REMOTE => {
            let p: api::CreateRemoteParams = parse(params)?;
            let code = STANDARD.decode(&p.code).map_err(|e| {
                (api::error_code::INVALID_PARAMS, format!("bad base64: {e}"))
            })?;
            let timeout = p.timeout_ms.unwrap_or(10_000);
            let r = ce_proc::create_remote(p.pid, &code, p.arg.unwrap_or(0), timeout).map_err(app)?;
            Ok(Response::ok(id, r))
        }
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
