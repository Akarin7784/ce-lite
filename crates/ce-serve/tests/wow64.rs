//! 集成测试：32 位（Wow64）目标支持。
//!
//! 前置条件：已构建 32 位目标进程
//! `cargo build -p ce-target --target i686-pc-windows-msvc`（CI 有对应步骤）。

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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

#[test]
fn wow64_process_attach_scan_and_debug() {
    // 32 位目标二进制（须已构建）。
    let target_exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/i686-pc-windows-msvc/debug/ce-target.exe"
    );
    let mut target = Command::new(target_exe)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn 32-bit ce-target");
    let mut t_out = BufReader::new(target.stdout.take().expect("ce-target stdout"));

    let mut line = String::new();
    t_out.read_line(&mut line).expect("read ADDR");
    let base = u64::from_str_radix(line.trim().trim_start_matches("ADDR=0x"), 16).unwrap();
    line.clear();
    t_out.read_line(&mut line).expect("read TICK");
    let tick = u64::from_str_radix(line.trim().trim_start_matches("TICK=0x"), 16).unwrap();
    let pid = target.id();

    let mut serve = Serve::spawn();

    // 1) attach：应识别为 32 位。
    let r = serve.rpc(1, "process.attach", &format!(r#"{{"pid":{pid}}}"#));
    let info = &r["result"];
    assert_eq!(info["arch"], serde_json::json!("x86"), "arch: {r}");
    assert_eq!(info["pointer_size"], serde_json::json!(4), "pointer_size: {r}");

    // 2) 值扫描（32 位进程内存语义一致）。
    let r = serve.rpc(2, "scan.new", r#"{"value_type":"int32","scan_type":"exact","value":100}"#);
    let scan_id = r["result"]["scan_id"].as_u64().unwrap();
    assert!(r["result"]["count"].as_u64().unwrap() >= 1, "scan: {r}");
    let r = serve.rpc(
        3,
        "scan.results",
        &format!(r#"{{"scan_id":{scan_id},"offset":0,"limit":1000}}"#),
    );
    let addrs: Vec<u64> = r["result"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["address"].as_u64().unwrap())
        .collect();
    assert!(addrs.contains(&(base + 0x10)), "should find 100 @ base+0x10: {r}");
    serve.rpc(4, "scan.close", &format!(r#"{{"scan_id":{scan_id}}}"#));

    // 3) 调试器：断点命中 + Wow64 寄存器读取。
    let r = serve.rpc(5, "debug.attach", &format!(r#"{{"pid":{pid}}}"#));
    assert_eq!(r["result"]["attached"], serde_json::json!(true), "debug attach: {r}");
    serve.rpc(6, "debug.breakpoint_set", &format!(r#"{{"address":{tick}}}"#));
    let r = serve.rpc(7, "debug.wait", r#"{"timeout_ms":5000}"#);
    let ev = &r["result"];
    assert_eq!(ev["kind"], "breakpoint", "expected breakpoint: {r}");
    let thread_id = ev["thread_id"].as_u64().unwrap() as u32;

    let r = serve.rpc(8, "debug.registers", &format!(r#"{{"thread_id":{thread_id}}}"#));
    let regs = &r["result"];
    let rip = regs["rip"].as_u64().unwrap();
    assert!(
        rip == tick || rip == tick + 1,
        "rip should be at 32-bit breakpoint: rip=0x{rip:x} tick=0x{tick:x}"
    );
    assert!(regs["rsp"].as_u64().unwrap() != 0, "esp mapped to rsp: {r}");
    assert!(
        regs["rip"].as_u64().unwrap() <= 0xFFFF_FFFF,
        "32-bit rip must fit in 32 bits: {r}"
    );

    // 4) 清理。
    serve.rpc(9, "debug.breakpoint_clear", &format!(r#"{{"address":{tick}}}"#));
    serve.rpc(10, "debug.continue", "{}");
    serve.rpc(11, "debug.detach", "{}");

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = target.kill();
    let _ = target.wait();
}
