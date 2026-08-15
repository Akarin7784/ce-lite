//! 集成测试：分析侧——调用栈回溯（断点命中后 debug.stack）。

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
fn debug_stack_walks_frames() {
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
    let _addr = u64::from_str_radix(line.trim().trim_start_matches("ADDR=0x"), 16).unwrap();
    line.clear();
    t_out.read_line(&mut line).expect("read TICK");
    let tick = u64::from_str_radix(line.trim().trim_start_matches("TICK=0x"), 16).unwrap();
    let t_pid = target.id();

    let mut serve = Serve::spawn();

    // process.attach（debug.stack 需要模块表标注返回地址）。
    serve.rpc(1, "process.attach", &format!(r#"{{"pid":{t_pid}}}"#));

    // 调试附加 + 断点。
    let r = serve.rpc(2, "debug.attach", &format!(r#"{{"pid":{t_pid}}}"#));
    assert_eq!(r["result"]["attached"], serde_json::json!(true));
    serve.rpc(3, "debug.breakpoint_set", &format!(r#"{{"address":{tick}}}"#));

    let r = serve.rpc(4, "debug.wait", r#"{"timeout_ms":5000}"#);
    let ev = &r["result"];
    assert_eq!(ev["kind"], "breakpoint", "expected breakpoint event: {r}");
    let thread_id = ev["thread_id"].as_u64().unwrap() as u32;

    // 回溯调用栈。
    let r = serve.rpc(
        5,
        "debug.stack",
        &format!(r#"{{"thread_id":{thread_id},"max_frames":16}}"#),
    );
    let res = &r["result"];
    let frames = res["frames"].as_array().expect("frames array");
    assert!(
        !frames.is_empty(),
        "expected at least one frame (thread is suspended at the breakpoint): {r}"
    );
    let first_rip = frames[0]["rip"].as_u64().unwrap();
    assert!(
        first_rip == tick || first_rip == tick + 1,
        "frame[0].rip should be at/near the breakpoint: rip=0x{first_rip:x} tick=0x{tick:x}"
    );
    assert!(
        frames[0]["rsp"].as_u64().unwrap() != 0,
        "frame[0].rsp must be valid"
    );

    // 清理：清断点 → 继续 → 分离。
    serve.rpc(6, "debug.breakpoint_clear", &format!(r#"{{"address":{tick}}}"#));
    serve.rpc(7, "debug.continue", "{}");
    serve.rpc(8, "debug.detach", "{}");

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = target.kill();
    let _ = target.wait();
}
