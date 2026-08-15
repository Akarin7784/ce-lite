//! 集成测试：结构体定义 + 按地址解析读取。

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
fn struct_define_and_read() {
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

    // 定义结构体（对应 ce-target 的数据布局）
    let r = serve.rpc(
        2,
        "struct.define",
        r#"{"name":"Test","fields":[{"name":"health","value_type":"int32","offset":16},{"name":"mana","value_type":"int32","offset":20},{"name":"score","value_type":"int32","offset":512}]}"#,
    );
    assert_eq!(r["result"]["defined"], serde_json::json!(true));

    // 按地址读取
    let r = serve.rpc(
        3,
        "struct.read",
        &format!(r#"{{"name":"Test","address":{}}}"#, addr),
    );
    let fields = r["result"]["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 3);

    let health = fields
        .iter()
        .find(|f| f["name"] == "health")
        .expect("health field");
    assert_eq!(health["value"], serde_json::json!(100));

    let mana = fields.iter().find(|f| f["name"] == "mana").expect("mana field");
    assert_eq!(mana["value"], serde_json::json!(200));

    let score = fields.iter().find(|f| f["name"] == "score").expect("score field");
    assert_eq!(score["value"], serde_json::json!(777));

    let _ = serve.child.kill();
    let _ = target.kill();
}
