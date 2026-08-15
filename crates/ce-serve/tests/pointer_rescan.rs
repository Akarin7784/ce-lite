//! 集成测试：指针扫描二次快照去噪。
//!
//! 跨进程验证完整链路：spawn `ce-target`（含一个会随时间翻转的 decoy 指针）→
//! 驱动 `ce-serve` 的 JSON-RPC stdio → `pointer.scan_start` → 等待 decoy 翻转 →
//! `pointer.rescan` → 断言候选数减少（不稳定指针被剔除）。

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

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
fn pointer_rescan_drops_unstable_pointer() {
    // 1. spawn ce-target 并解析其堆基址
    let target_exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/debug/ce-target.exe"
    );
    let mut target = Command::new(target_exe)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn ce-target");
    let mut t_stdout = BufReader::new(target.stdout.take().expect("ce-target stdout"));
    let mut addr_line = String::new();
    t_stdout.read_line(&mut addr_line).expect("read ADDR");
    let addr = u64::from_str_radix(addr_line.trim().trim_start_matches("ADDR=0x"), 16)
        .expect("parse ADDR");
    let t_pid = target.id();

    // 2. spawn ce-serve 并驱动
    let mut serve = Serve::spawn();

    serve.rpc(1, "process.attach", &format!(r#"{{"pid":{}}}"#, t_pid));
    let value_addr = addr + 0x200;

    let r = serve.rpc(
        2,
        "pointer.scan_start",
        &format!(
            r#"{{"address":{},"max_offset":4096,"max_depth":2,"pointer_size":8}}"#,
            value_addr
        ),
    );
    let scan_id = r["result"]["scan_id"].as_u64().expect("scan_id");
    let before = r["result"]["count"].as_u64().expect("count");
    assert!(before > 0, "first scan should find candidates");

    // 3. 等待 decoy 指针翻转（2s 后变成 0xDEAD）
    sleep(Duration::from_millis(2600));

    let r2 = serve.rpc(3, "pointer.rescan", &format!(r#"{{"scan_id":{}}}"#, scan_id));
    let after = r2["result"]["count"].as_u64().expect("count after rescan");
    assert!(
        after < before,
        "rescan should drop the unstable decoy pointer (before={before}, after={after})"
    );

    // 4. 结果可读且关闭成功
    let r3 = serve.rpc(
        4,
        "pointer.results",
        &format!(r#"{{"scan_id":{},"offset":0,"limit":100}}"#, scan_id),
    );
    assert_eq!(r3["result"]["total"].as_u64().unwrap(), after);

    serve.rpc(5, "pointer.close", &format!(r#"{{"scan_id":{}}}"#, scan_id));

    // 5. 清理
    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = target.kill();
    let _ = target.wait();
}
