//! `ce-serve` bin — JSON-RPC 2.0 over stdio 守护进程。
//!
//! 从 stdin 逐行读取请求，向 stdout 逐行写回响应（newline-delimited JSON）。
//! 这是 AI 代理（如 DeepSeek Harness 插件经 `subprocess`）驱动的入口。
//! 分发逻辑在 `lib.rs`（`ce_serve` crate），此处只做 stdio 桥接。

use std::io::{self, BufRead, Write};

use ce_core::api::{self, Response};
use ce_serve::{dispatch, parse_compact_spec, Session};

fn main() -> io::Result<()> {
    // CLI 一次性模式：ce-serve --one-shot <method> [json-params]
    // 或紧凑形式 ce-serve --one-shot "scan:int32:exact:100"
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--one-shot" {
        let mut session = Session::new();
        let (method, params) = if args[2].contains(':') && !args[2].starts_with('{') {
            parse_compact_spec(&args[2])
        } else {
            let params: serde_json::Value = args
                .get(3)
                .map(|s| serde_json::from_str(s).unwrap_or(serde_json::Value::Null))
                .unwrap_or(serde_json::Value::Null);
            (args[2].clone(), params)
        };
        let resp = match dispatch(&mut session, 1, &method, params) {
            Ok(r) => r,
            Err((code, msg)) => Response::err(1, code, msg),
        };
        println!("{}", serde_json::to_string(&resp)?);
        return Ok(());
    }

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
