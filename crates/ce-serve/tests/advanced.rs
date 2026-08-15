//! 集成测试：高级功能——新扫描类型、指针分析、反汇编工具链、AOB 模块扫描、
//! 训练器 freeze、内联钩子、会话持久化、访问者闭环、CLI 一次性模式。

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::Engine as _;

struct Serve {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Serve {
    fn spawn() -> Self {
        let exe = env!("CARGO_BIN_EXE_ce-serve");
        let mut child = Command::new(exe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ce-serve");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Serve {
            child,
            stdin,
            stdout,
        }
    }

    fn rpc(&mut self, id: u64, method: &str, params: &str) -> serde_json::Value {
        writeln!(
            self.stdin,
            r#"{{"jsonrpc":"2.0","id":{},"method":"{}","params":{}}}"#,
            id, method, params
        )
        .expect("write request");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        serde_json::from_str(&line).expect("parse response")
    }
}

struct Target {
    child: Child,
    base: u64,
    tick: u64,
    pid: u32,
}

fn spawn_target() -> Target {
    // 测试前需先 `cargo build -p ce-target`（CI 与本地均显式构建，见 README）。
    let target_exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/debug/ce-target.exe"
    );
    let mut child = Command::new(target_exe)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn ce-target");
    let mut t_out = BufReader::new(child.stdout.take().expect("ce-target stdout"));
    let mut line = String::new();
    t_out.read_line(&mut line).expect("read ADDR");
    let base = u64::from_str_radix(line.trim().trim_start_matches("ADDR=0x"), 16).unwrap();
    line.clear();
    t_out.read_line(&mut line).expect("read TICK");
    let tick = u64::from_str_radix(line.trim().trim_start_matches("TICK=0x"), 16).unwrap();
    let pid = child.id();
    Target { child, base, tick, pid }
}

fn read_i32(serve: &mut Serve, id: u64, addr: u64) -> i32 {
    let r = serve.rpc(id, "memory.read", &format!(r#"{{"address":{addr},"size":4}}"#));
    let bytes = r["result"]["bytes"].as_str().unwrap();
    let raw = base64::engine::general_purpose::STANDARD.decode(bytes).unwrap();
    i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
}

fn attach(serve: &mut Serve, t: &Target) {
    let r = serve.rpc(1, "process.attach", &format!(r#"{{"pid":{}}}"#, t.pid));
    assert!(r["result"].is_object(), "attach failed: {r}");
}

#[test]
fn advanced_scan_types() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);
    let b = t.base;

    // between：150 ∈ [100, 200]（0x800），且 100/200 也在区间内。
    let r = serve.rpc(10, "scan.new", r#"{"value_type":"int32","scan_type":"between","min":100,"max":200}"#);
    let scan_id = r["result"]["scan_id"].as_u64().unwrap();
    assert!(r["result"]["count"].as_u64().unwrap() >= 3);
    let r = serve.rpc(
        11,
        "scan.results",
        &format!(r#"{{"scan_id":{scan_id},"offset":0,"limit":1000}}"#),
    );
    let addrs: Vec<u64> = r["result"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["address"].as_u64().unwrap())
        .collect();
    assert!(addrs.contains(&(b + 0x800)), "between should find 150 @ 0x800: {r}");
    serve.rpc(12, "scan.close", &format!(r#"{{"scan_id":{scan_id}}}"#));

    // rounded：99.6 @ 0x700 → round=100（进程内可能有其它四舍五入到 100 的噪声值）。
    let r = serve.rpc(
        13,
        "scan.new",
        r#"{"value_type":"float","scan_type":"rounded","value":100}"#,
    );
    let scan_id = r["result"]["scan_id"].as_u64().unwrap();
    assert!(r["result"]["count"].as_u64().unwrap() >= 1, "rounded: {r}");
    let r = serve.rpc(
        14,
        "scan.results",
        &format!(r#"{{"scan_id":{scan_id},"offset":0,"limit":1000}}"#),
    );
    let addrs: Vec<u64> = r["result"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["address"].as_u64().unwrap())
        .collect();
    assert!(addrs.contains(&(b + 0x700)), "rounded should find 99.6 @ 0x700: {r}");
    serve.rpc(15, "scan.close", &format!(r#"{{"scan_id":{scan_id}}}"#));

    // XOR：0x600 存的是逐字节 XOR 0x55 的 777。
    let r = serve.rpc(
        16,
        "scan.new",
        r#"{"value_type":"int32","scan_type":"exact","value":777,"xor_key":85}"#,
    );
    let scan_id = r["result"]["scan_id"].as_u64().unwrap();
    assert_eq!(r["result"]["count"].as_u64().unwrap(), 1, "xor: {r}");
    let r = serve.rpc(
        17,
        "scan.results",
        &format!(r#"{{"scan_id":{scan_id},"offset":0,"limit":10}}"#),
    );
    assert_eq!(
        r["result"]["results"][0]["address"].as_u64().unwrap(),
        b + 0x600
    );
    serve.rpc(18, "scan.close", &format!(r#"{{"scan_id":{scan_id}}}"#));

    // AOB 通配符：DE ?? BE EF ?? FE 命中 0x100。
    let r = serve.rpc(
        19,
        "scan.new",
        r#"{"value_type":"bytes","scan_type":"exact","value":[222,0,190,239,0,254],"mask":[255,0,255,255,0,255]}"#,
    );
    let scan_id = r["result"]["scan_id"].as_u64().unwrap();
    let r = serve.rpc(
        20,
        "scan.results",
        &format!(r#"{{"scan_id":{scan_id},"offset":0,"limit":1000}}"#),
    );
    let addrs: Vec<u64> = r["result"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["address"].as_u64().unwrap())
        .collect();
    assert!(addrs.contains(&(b + 0x100)), "wildcard AOB: {r}");
    serve.rpc(21, "scan.close", &format!(r#"{{"scan_id":{scan_id}}}"#));

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn pointer_analyze_and_struct_spawn() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);
    let target_addr = t.base + 0x200; // 777 值

    let r = serve.rpc(
        30,
        "pointer.scan_start",
        &format!(r#"{{"address":{target_addr},"max_offset":4096,"max_depth":3,"pointer_size":8}}"#),
    );
    let scan_id = r["result"]["scan_id"].as_u64().unwrap();
    assert!(r["result"]["count"].as_u64().unwrap() >= 1);

    // 分析：偏移聚类 + union。
    let r = serve.rpc(31, "pointer.analyze", &format!(r#"{{"scan_id":{scan_id}}}"#));
    let analysis = &r["result"];
    assert!(analysis["top_offsets"].is_array());
    assert!(analysis["unions"].is_array());
    assert!(
        !analysis["unions"].as_array().unwrap().is_empty(),
        "expected at least one union: {r}"
    );

    // structure spawn。
    let r = serve.rpc(
        32,
        "pointer.struct_spawn",
        &format!(r#"{{"scan_id":{scan_id}}}"#),
    );
    let fields = r["result"]["fields"].as_array().unwrap();
    assert!(!fields.is_empty(), "expected spawned fields: {r}");

    serve.rpc(33, "pointer.close", &format!(r#"{{"scan_id":{scan_id}}}"#));
    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn disasm_function_boundary() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);

    let r = serve.rpc(
        40,
        "disasm.function",
        &format!(r#"{{"address":{}}}"#, t.tick),
    );
    let res = &r["result"];
    assert!(res["size"].as_u64().unwrap() > 0, "function: {r}");
    assert!(
        !res["instructions"].as_array().unwrap().is_empty(),
        "instructions: {r}"
    );
    assert!(
        res["start"].as_u64().unwrap() <= t.tick,
        "start should be <= tick"
    );

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn module_aob_scan() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);

    // 无模块限制：命中堆上的 AOB @ 0x100。
    let r = serve.rpc(50, "module.aob_scan", r#"{"pattern":"DE ?? BE EF"}"#);
    let hits: Vec<u64> = r["result"]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert!(hits.contains(&(t.base + 0x100)), "aob hits: {r}");

    // 限定不存在的模块 → 明确错误。
    let r = serve.rpc(51, "module.aob_scan", r#"{"pattern":"DE AD","module":"nope.dll"}"#);
    assert!(r["error"].is_object(), "expected error: {r}");

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn trainer_freeze_and_patch_export() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);

    // 先把 0x800 写成 42，再 freeze 写回 150。
    let b42 = base64::engine::general_purpose::STANDARD.encode(42i32.to_le_bytes());
    let r = serve.rpc(
        60,
        "memory.write",
        &format!(r#"{{"address":{},"bytes":"{b42}"}}"#, t.base + 0x800),
    );
    assert_eq!(r["result"]["written"].as_u64().unwrap(), 4, "write 42: {r}");
    assert_eq!(read_i32(&mut serve, 61, t.base + 0x800), 42);

    let r = serve.rpc(
        62,
        "trainer.freeze",
        &format!(r#"{{"address":{},"bytes":"{b64}","interval_ms":10}}"#,
            t.base + 0x800,
            b64 = base64::engine::general_purpose::STANDARD.encode(150i32.to_le_bytes())),
    );
    let freeze_id = r["result"]["freeze_id"].as_u64().unwrap();

    std::thread::sleep(std::time::Duration::from_millis(300));
    let v = read_i32(&mut serve, 63, t.base + 0x800);
    assert_eq!(v, 150, "freeze should restore 150");

    let r = serve.rpc(64, "trainer.list", "{}");
    assert_eq!(r["result"]["freezes"].as_array().unwrap().len(), 1);

    serve.rpc(65, "trainer.unfreeze", &format!(r#"{{"freeze_id":{freeze_id}}}"#));

    // 补丁导出应包含对 0x800 的写入。
    let r = serve.rpc(66, "patch.export", "{}");
    let patches = r["result"]["patches"].as_array().unwrap();
    assert!(
        patches.iter().any(|p| p["address"].as_u64().unwrap() == t.base + 0x800),
        "patch export: {r}"
    );

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn hook_install_and_remove() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);

    // 钩子代码：xor eax,eax; ret。
    let hook_b64 = base64::engine::general_purpose::STANDARD.encode([0x31, 0xC0, 0xC3]);
    let r = serve.rpc(
        70,
        "hook.install",
        &format!(r#"{{"address":{},"hook":"{hook_b64}"}}"#, t.tick),
    );
    let res = &r["result"];
    assert_eq!(res["installed"], serde_json::json!(true), "hook: {r}");
    assert!(res["trampoline"].as_u64().unwrap() > 0);
    assert!(res["hook_cave"].as_u64().unwrap() > 0);
    assert!(res["patch_len"].as_u64().unwrap() >= 5);

    let r = serve.rpc(71, "hook.list", "{}");
    assert_eq!(r["result"]["hooks"].as_array().unwrap().len(), 1);

    let r = serve.rpc(72, "hook.remove", &format!(r#"{{"address":{}}}"#, t.tick));
    assert_eq!(r["result"]["removed"], serde_json::json!(true), "unhook: {r}");
    let r = serve.rpc(73, "hook.list", "{}");
    assert_eq!(r["result"]["hooks"].as_array().unwrap().len(), 0);

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn session_save_load_across_instances() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);

    // 定义结构体 + 指针扫描，保存会话。
    let r = serve.rpc(
        80,
        "struct.define",
        r#"{"name":"Test","fields":[{"name":"hp","value_type":"int32","offset":16}]}"#,
    );
    assert_eq!(r["result"]["defined"], serde_json::json!(true), "struct.define: {r}");
    let r = serve.rpc(
        81,
        "pointer.scan_start",
        &format!(r#"{{"address":{},"max_offset":4096,"max_depth":1,"pointer_size":8}}"#, t.base + 0x200),
    );
    assert!(r["result"].is_object(), "scan_start failed: {r}");

    let r = serve.rpc(82, "session.save", "{}");
    let data = r["result"]["data"].as_str().unwrap().to_string();

    // 新实例加载。
    let mut serve2 = Serve::spawn();
    let r = serve2.rpc(83, "session.load", &format!(r#"{{"data":"{data}"}}"#));
    assert_eq!(r["result"]["loaded"], serde_json::json!(true), "load: {r}");
    let r = serve2.rpc(84, "struct.list", "{}");
    assert!(r["result"].as_array().unwrap().contains(&serde_json::json!("Test")));
    let r = serve2.rpc(85, "trainer.list", "{}"); // 训练器状态也恢复（无）
    assert!(r["result"]["freezes"].is_array());

    let _ = serve2.child.kill();
    let _ = serve2.child.wait();
    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn debug_accessor_reports_rip_instruction() {
    let mut t = spawn_target();
    let mut serve = Serve::spawn();
    attach(&mut serve, &t);

    let r = serve.rpc(90, "debug.attach", &format!(r#"{{"pid":{}}}"#, t.pid));
    assert_eq!(r["result"]["attached"], serde_json::json!(true));
    serve.rpc(91, "debug.breakpoint_set", &format!(r#"{{"address":{}}}"#, t.tick));
    let r = serve.rpc(92, "debug.wait", r#"{"timeout_ms":5000}"#);
    let ev = &r["result"];
    assert_eq!(ev["kind"], "breakpoint");
    let thread_id = ev["thread_id"].as_u64().unwrap() as u32;

    let r = serve.rpc(
        93,
        "debug.accessor",
        &format!(r#"{{"thread_id":{thread_id}}}"#),
    );
    let res = &r["result"];
    let rip = res["rip"].as_u64().unwrap();
    assert!(
        rip == t.tick || rip == t.tick + 1,
        "rip should be at tick: rip=0x{rip:x} tick=0x{:x}",
        t.tick
    );
    assert!(res["instruction"].is_object(), "instruction: {r}");
    assert!(res["registers"]["rsp"].as_u64().unwrap() != 0);

    // PDB 解析形状（ce-target 无 PDB 时 name 为 null）。
    let r = serve.rpc(94, "symbols.pdb_resolve", &format!(r#"{{"address":{}}}"#, t.tick));
    assert!(r["result"]["name"].is_null() || r["result"]["name"].is_string());

    serve.rpc(95, "debug.breakpoint_clear", &format!(r#"{{"address":{}}}"#, t.tick));
    serve.rpc(96, "debug.continue", "{}");
    serve.rpc(97, "debug.detach", "{}");

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = t.child.kill();
    let _ = t.child.wait();
}

#[test]
fn cli_one_shot_mode() {
    let exe = env!("CARGO_BIN_EXE_ce-serve");
    // process.list 一次性调用。
    let out = Command::new(exe)
        .args(["--one-shot", "process.list", "{}"])
        .output()
        .expect("run one-shot");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json output");
    assert!(v["result"].is_array(), "process.list one-shot: {stdout}");
}
