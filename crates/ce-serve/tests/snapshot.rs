//! 集成测试：内存快照 + 差异比对。

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
fn snapshot_diff_finds_changes() {
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

    serve.rpc(1, "process.attach", &format!(r#"{{"pid":{}}}"#, t_pid));

    // 快照 addr 起 64 字节（snapshot_id = 1）
    let r = serve.rpc(
        2,
        "memory.snapshot",
        &format!(r#"{{"address":{},"size":64}}"#, addr),
    );
    let snapshot_id = r["result"]["snapshot_id"].as_u64().unwrap();
    assert_eq!(snapshot_id, 1);

    // 修改 addr+0x10 处 4 字节（100 → 999 = E7 03 00 00）
    let new_val = base64_encode(&999i32.to_le_bytes());
    serve.rpc(
        3,
        "memory.write",
        &format!(
            r#"{{"address":{},"bytes":"{}"}}"#,
            addr + 0x10,
            new_val
        ),
    );

    // 差异比对
    let r = serve.rpc(
        4,
        "memory.diff",
        &format!(r#"{{"snapshot_id":{}}}"#, snapshot_id),
    );
    let changes = r["result"]["changes"].as_array().unwrap();
    // 999i32 = E7 03 00 00，相对原值 64 00 00 00 改了低两字节
    assert_eq!(changes.len(), 2, "should find two changed bytes");
    assert_eq!(changes[0]["offset"].as_u64().unwrap(), 0x10);
    assert_eq!(changes[0]["old"].as_u64().unwrap(), 0x64); // 原值 100 低字节
    assert_eq!(changes[0]["new"].as_u64().unwrap(), 0xE7); // 新值 999 低字节
    assert_eq!(changes[1]["offset"].as_u64().unwrap(), 0x11);
    assert_eq!(changes[1]["new"].as_u64().unwrap(), 0x03);

    let _ = serve.child.kill();
    let _ = serve.child.wait();
    let _ = target.kill();
    let _ = target.wait();
}

fn base64_encode(bytes: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
