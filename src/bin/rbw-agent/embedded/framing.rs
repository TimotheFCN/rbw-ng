// How requests, answers and events are written on the wire: see
// docs/embedding.md › Messages.

use serde_json::{json, Value};

// A request id: a string of at most this many bytes, or an integer.
const MAX_ID: usize = 64;

// An account id names the account's folder, so it is letters, digits, _ and
// - only, at most this long.
const MAX_ACCOUNT: usize = 64;

pub fn valid_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= MAX_ACCOUNT
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// A message from the host, read.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    Request {
        id: Value,
        verb: String,
        params: Value,
        deadline: Option<std::time::Duration>,
        // which account, for an agent serving several (--accounts)
        account: Option<String>,
    },
    Cancel(Value),
    // a message that gets an error back at once
    Refuse(Value),
    Ignore,
}

fn valid_id(id: &Value) -> bool {
    match id {
        Value::String(id) => !id.is_empty() && id.len() <= MAX_ID,
        Value::Number(id) => id.is_i64() || id.is_u64(),
        _ => false,
    }
}

fn deadline(ms: Option<&Value>) -> Option<std::time::Duration> {
    ms.and_then(Value::as_u64)
        .filter(|ms| *ms > 0)
        .map(std::time::Duration::from_millis)
}

// The first message: the agent says what it is.
pub fn start(ready: &Value) -> Value {
    json!({ "event": "ready", "data": ready })
}

pub fn event(event: &str, data: &Value, account: Option<&str>) -> Value {
    let mut message = json!({ "event": event, "data": data });
    if let Some(account) = account {
        message["account"] = Value::String(account.to_string());
    }
    message
}

// The answer to a request. A verb's error is an answer too.
pub fn answer(id: &Value, answer: Result<Value, Value>) -> Value {
    match answer {
        Ok(result) => json!({ "id": id, "result": result }),
        Err(error) => json!({ "id": id, "error": error }),
    }
}

fn refuse(id: &Value, message: &str) -> Incoming {
    Incoming::Refuse(answer(
        id,
        Err(json!({ "code": "bad_request", "message": message })),
    ))
}

// {"id", "method", "params", "deadline", "account"} and {"cancel": id}
pub fn read(message: &Value) -> Incoming {
    if let Some(id) = message.get("cancel") {
        return if valid_id(id) {
            Incoming::Cancel(id.clone())
        } else {
            Incoming::Ignore
        };
    }
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    if !valid_id(&id) {
        return refuse(
            &Value::Null,
            "A request needs an id: a short string or an integer.",
        );
    }
    let Some(verb) = message.get("method").and_then(Value::as_str) else {
        return refuse(&id, "A request needs a method.");
    };
    let account = match message.get("account") {
        None => None,
        Some(Value::String(account)) if valid_account(account) => {
            Some(account.clone())
        }
        Some(_) => {
            return refuse(
                &id,
                "An account id is 1 to 64 letters, digits, _ or -.",
            )
        }
    };
    Incoming::Request {
        verb: verb.to_string(),
        params: message.get("params").cloned().unwrap_or(Value::Null),
        deadline: deadline(message.get("deadline")),
        account,
        id,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accounts() {
        assert!(matches!(
            read(&json!({"id": 1, "method": "items", "account": "work-1"})),
            Incoming::Request { account: Some(ref a), .. } if a == "work-1"
        ));
        for bad in [
            json!(""),
            json!("../etc"),
            json!("a b"),
            json!(4),
            json!("x".repeat(65)),
        ] {
            assert!(
                matches!(
                    read(
                        &json!({"id": 1, "method": "items", "account": bad})
                    ),
                    Incoming::Refuse(_)
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn requests() {
        assert_eq!(
            read(&json!({
                "id": 7, "method": "fill", "params": {"id": "x"}, "deadline": 500
            })),
            Incoming::Request {
                id: json!(7),
                verb: "fill".to_string(),
                params: json!({"id": "x"}),
                deadline: Some(std::time::Duration::from_millis(500)),
                account: None,
            }
        );
        assert_eq!(
            read(&json!({"cancel": "a"})),
            Incoming::Cancel(json!("a"))
        );
        assert_eq!(read(&json!({"cancel": {}})), Incoming::Ignore);
        assert!(matches!(
            read(&json!({"method": "fill"})),
            Incoming::Refuse(_)
        ));
        assert!(matches!(
            read(&json!({"id": "x".repeat(65), "method": "fill"})),
            Incoming::Refuse(_)
        ));
        assert!(matches!(read(&json!({"id": 1})), Incoming::Refuse(_)));
    }

    #[test]
    fn answers() {
        assert_eq!(
            answer(&json!(3), Ok(json!({"ok": true}))),
            json!({"id": 3, "result": {"ok": true}})
        );
        assert_eq!(
            answer(&json!(3), Err(json!({"code": "locked"}))),
            json!({"id": 3, "error": {"code": "locked"}})
        );
        assert_eq!(
            event("state", &json!({"state": "locked"}), None),
            json!({"event": "state", "data": {"state": "locked"}})
        );
        assert_eq!(
            event("state", &json!({"state": "locked"}), Some("work")),
            json!({"event": "state", "account": "work", "data": {"state": "locked"}})
        );
    }
}
