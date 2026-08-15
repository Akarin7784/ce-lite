//! 集成测试：分析侧——远程线程注入（代码注入 + DLL 注入）。

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

/// 构造 x64 shellcode：`mov rax, imm64; mov dword [rax], 0x12345678; xor eax, eax; ret`。
fn write_immediate_shellcode(addr: u64) -> Vec<u8> {
    let mut code = vec![0x48, 0xB8]; // mov rax, imm64
    code.extend_from_slice(&addr.to_le_bytes());
    code.extend_from_slice(&[0xC7, 0x00, 0x78, 0x56, 0x34, 0x12]); // mov dword [rax], 0x12345678
    code.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    code.push(0xC3); // ret
    code
}

fn spawn_target() -> (Child, u64) {
    let target_exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/debug/ce-target.exe"
    );
    let mut target = Command::new(target_exe)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn ce-target");
    let mut t_out = BufReader::new(target.stdout.take().expect("ce-target stdout"));
    let mut line = String::new();
    t_out.read_line(&mut line).expect("read ADDR");
    let addr = u64::from_str_radix(line.trim().trim_start_matches("ADDR=0x"), 16).unwrap();
    (target, addr)
}

#[test]
fn create_remote_runs_shellcode() {
    let (mut target, base) = spawn_target();
    let pid = target.id();
    let mut serve = Serve::spawn();

    // 附加（为后续 memory.read 提供进程句柄）。
    let r = serve.rpc(1, "process.attach", &format!(r#"{{"pid":{pid}}}"#));
    assert!(r["result"].is_object(), "attach failed: {r}");

    // 注入 shellcode：把 0x12345678 写入 base+0x400。
    let code = write_immediate_shellcode(base + 0x400);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&code);
    let r = serve.rpc(
        2,
        "thread.create_remote",
        &format!(r#"{{"pid":{pid},"code":"{b64}","timeout_ms":5000}}"#),
    );
    let res = &r["result"];
    assert_eq!(res["completed"], serde_json::json!(true), "inject failed: {r}");
    assert_eq!(res["exit_code"], serde_json::json!(0));
    assert!(res["thread_id"].as_u64().unwrap() > 0);

    // 验证写入生效。
    let r = serve.rpc(
        3,
        "memory.read",
        &format!(r#"{{"address":{},"size":4}}"#, base + 0x400),
    );
    let bytes = r["result"]["bytes"].as_str().unwrap();
    let raw = base64::engine::general_purpose::STANDARD.decode(bytes).unwrap();
    let val = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    assert_eq!(val, 0x12345678, "shellcode write did not land");

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = target.kill();
    let _ = target.wait();
}

#[test]
fn inject_dll_loads_system_dll() {
    let (mut target, _base) = spawn_target();
    let pid = target.id();
    let mut serve = Serve::spawn();

    // 注入已加载的系统 DLL：LoadLibraryW 返回非零句柄 → 退出码非零。
    let params = r#"{"pid":%PID%,"path":"C:\\Windows\\System32\\kernel32.dll","timeout_ms":5000}"#
        .replace("%PID%", &pid.to_string());
    let r = serve.rpc(1, "thread.inject_dll", &params);
    let res = &r["result"];
    assert_eq!(res["completed"], serde_json::json!(true), "inject failed: {r}");
    assert!(
        res["exit_code"].as_u64().unwrap() != 0,
        "LoadLibraryW returned NULL: {r}"
    );
    assert!(res["thread_id"].as_u64().unwrap() > 0);

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = target.kill();
    let _ = target.wait();
}
