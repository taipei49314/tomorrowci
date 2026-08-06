use sha2::{Digest, Sha256};

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("sha256:{}", hex::encode(h.finalize()))
}

pub fn sha256_str(s: &str) -> String {
    sha256_bytes(s.as_bytes())
}

pub fn canonical_json_hash<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    let s = serde_json::to_string(&canonicalize(&v))?;
    Ok(sha256_str(&s))
}

fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonicalize(&map[&k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_stable() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(
            canonical_json_hash(&a).unwrap(),
            canonical_json_hash(&b).unwrap()
        );
    }
}
