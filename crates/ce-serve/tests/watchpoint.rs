//! 集成测试：硬件监视点（找出写某地址的代码）。

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
fn watchpoint_triggers_on_write() {
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
    let t_pid = target.id();

    let mut serve = Serve::spawn();

    // attach
    let r = serve.rpc(1, "debug.attach", &format!(r#"{{"pid":{}}}"#, t_pid));
    assert_eq!(r["result"]["attached"], serde_json::json!(true));

    // 设置写监视点（4 字节，监视 addr+0x300，后台线程每 20ms 写一次）
    let watched = addr + 0x300;
    let r = serve.rpc(
        2,
        "debug.watchpoint_set",
        &format!(r#"{{"address":{},"size":4,"on_write":true}}"#, watched),
    );
    assert_eq!(r["result"]["set"], serde_json::json!(true));

    // 等待监视点触发
    let r = serve.rpc(3, "debug.wait", r#"{"timeout_ms":5000}"#);
    let ev = &r["result"];
    assert_eq!(ev["kind"], "watchpoint", "expected watchpoint event");
    assert_eq!(ev["address"].as_u64().unwrap(), watched);
    let access = ev["access"].as_str().unwrap_or("");
    assert!(access == "write" || access == "read_write", "access={access}");
    let thread_id = ev["thread_id"].as_u64().unwrap() as u32;

    // 读寄存器确认 RIP 有效（写指令之后）
    let r = serve.rpc(
        4,
        "debug.registers",
        &format!(r#"{{"thread_id":{}}}"#, thread_id),
    );
    let rip1 = r["result"]["rip"].as_u64().expect("rip readable");

    // 单步执行一条指令
    serve.rpc(
        5,
        "debug.single_step",
        &format!(r#"{{"thread_id":{}}}"#, thread_id),
    );
    let r = serve.rpc(6, "debug.wait", r#"{"timeout_ms":5000}"#);
    let ev = &r["result"];
    assert_eq!(ev["kind"], "single_step", "expected single_step event");

    let r = serve.rpc(
        7,
        "debug.registers",
        &format!(r#"{{"thread_id":{}}}"#, thread_id),
    );
    let rip2 = r["result"]["rip"].as_u64().expect("rip readable after step");
    assert!(rip2 > rip1, "rip should advance after single step: {rip1} -> {rip2}");

    // 继续
    serve.rpc(8, "debug.continue", "{}");

    // 清除监视点 + 分离
    serve.rpc(
        9,
        "debug.watchpoint_clear",
        &format!(r#"{{"address":{}}}"#, watched),
    );
    serve.rpc(10, "debug.detach", "{}");

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = target.kill();
    let _ = target.wait();
}
