//! 值解释与比较原语：字节 ↔ 值类型、相等/数值比较。
//!
//! 纯函数、平台无关、可单元测试。对应 Cheat Engine 的 `byteinterpreter.pas`。

use crate::{Value, ValueType};

/// 从内存字节解释为一个值（小端）。
///
/// 数值类型按 CE 语义：`Byte` 为无符号，`Int16/32/64` 为有符号，
/// `Float/Double` 为 IEEE-754。
pub fn from_bytes(bytes: &[u8], vt: ValueType) -> Option<Value> {
    match vt {
        ValueType::Byte => Some(Value::Int(*bytes.first()? as i64)),
        ValueType::Int16 => Some(Value::Int(
            i16::from_le_bytes(bytes.get(..2)?.try_into().ok()?) as i64,
        )),
        ValueType::Int32 => Some(Value::Int(
            i32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as i64,
        )),
        ValueType::Int64 => Some(Value::Int(i64::from_le_bytes(
            bytes.get(..8)?.try_into().ok()?,
        ))),
        ValueType::Float => Some(Value::Float(f32::from_le_bytes(
            bytes.get(..4)?.try_into().ok()?,
        ))),
        ValueType::Double => Some(Value::Double(f64::from_le_bytes(
            bytes.get(..8)?.try_into().ok()?,
        ))),
        ValueType::Bytes | ValueType::Binary => Some(Value::Bytes(bytes.to_vec())),
        ValueType::String => None,
    }
}

/// 一次匹配所需读取的字节宽度。
pub fn width(vt: ValueType, value: &Value) -> usize {
    match vt {
        ValueType::Bytes | ValueType::Binary => match value {
            Value::Bytes(b) => b.len(),
            _ => 0,
        },
        ValueType::String => match value {
            Value::Str(s) => s.len(),
            _ => 0,
        },
        _ => vt.size().unwrap_or(0),
    }
}

/// 内存字节是否与目标值“相等”。
///
/// 字节/字符串：前缀字节相等（即该处为模式起点）；数值：解释后相等。
pub fn equals(bytes: &[u8], vt: ValueType, value: &Value) -> bool {
    match (vt, value) {
        (ValueType::String, Value::Str(s)) => bytes.starts_with(s.as_bytes()),
        (ValueType::Bytes | ValueType::Binary, Value::Bytes(b)) => bytes.starts_with(b),
        _ => from_bytes(bytes, vt)
            .map(|v| v == *value)
            .unwrap_or(false),
    }
}

/// 值到数值（用于增大/减小/大于/小于等比较）。
///
/// 注意：以 `f64` 近似，`Int64` 超过 2^53 时比较精度下降；
/// 精确比较走 `equals`（字节级）路径。
pub fn numeric(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f as f64),
        Value::Double(d) => Some(*d),
        _ => None,
    }
}

/// 内存字节对应的数值（先解释再转 f64）。
pub fn numeric_of(bytes: &[u8], vt: ValueType) -> Option<f64> {
    from_bytes(bytes, vt).and_then(|v| numeric(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int32_little_endian() {
        let bytes = 100i32.to_le_bytes();
        assert_eq!(from_bytes(&bytes, ValueType::Int32), Some(Value::Int(100)));
    }

    #[test]
    fn byte_unsigned() {
        assert_eq!(from_bytes(&[255], ValueType::Byte), Some(Value::Int(255)));
    }

    #[test]
    fn double_roundtrip() {
        let bytes = 3.5f64.to_le_bytes();
        assert_eq!(
            from_bytes(&bytes, ValueType::Double),
            Some(Value::Double(3.5))
        );
    }

    #[test]
    fn equals_exact_int() {
        let bytes = 100i32.to_le_bytes();
        assert!(equals(&bytes, ValueType::Int32, &Value::Int(100)));
        assert!(!equals(&bytes, ValueType::Int32, &Value::Int(101)));
    }

    #[test]
    fn equals_aob_prefix() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(equals(&bytes, ValueType::Bytes, &Value::Bytes(vec![0xDE, 0xAD])));
        assert!(!equals(&bytes, ValueType::Bytes, &Value::Bytes(vec![0xAD, 0xBE])));
    }
}
