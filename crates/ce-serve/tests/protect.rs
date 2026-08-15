//! 集成测试：防护侧——反作弊感知 + attach 错误分类。

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
fn protect_status_shape() {
    let mut serve = Serve::spawn();
    let r = serve.rpc(1, "protect.status", "{}");
    let res = &r["result"];
    assert!(res["detected"].is_array(), "detected must be an array");
    assert!(res["protected"].is_boolean(), "protected must be a bool");
    assert!(
        res["kernel_protection"].is_boolean(),
        "kernel_protection must be a bool"
    );
    let _ = serve.child.kill();
    let _ = serve.child.wait();
}

#[test]
fn attach_classifies_not_found() {
    let mut serve = Serve::spawn();
    // 不存在的 pid：应返回分类错误（not found），而非未分类的通用错误。
    let r = serve.rpc(1, "process.attach", r#"{"pid":4294967295}"#);
    let err = &r["error"];
    assert_eq!(err["code"], serde_json::json!(-32000));
    let msg = err["message"].as_str().unwrap();
    assert!(
        msg.contains("not found") || msg.contains("failed"),
        "unexpected message: {msg}"
    );
    let _ = serve.child.kill();
    let _ = serve.child.wait();
}
