//! Control protocol between the daemon and the in-sandbox `sandlock-init`.
//! Newline-delimited JSON; `RunExec` additionally carries 3 SCM_RIGHTS fds.
//!
//! Every verb is **instance-level**: `RunMain`/`RunExec` spawn registered
//! children, `Shutdown` tears the whole container down, and `Signal` delivers
//! `signum` to every registered child group. There is deliberately **no**
//! pid-addressed signal verb: a frame on this channel (which a compromised
//! workload could hold, SL-4) must never be able to name an arbitrary process
//! for the host to signal. Direct same-uid `kill(2)` between sandbox
//! processes is a kernel boundary sandlock does not mediate (see
//! `docs/sandbox-exec-security.md` §4.6/§4.15).
use serde::{Deserialize, Serialize};

/// Fixed fd number the daemon maps the control channel onto in the child.
pub const CONTROL_FD: i32 = 3;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "req", rename_all = "lowercase")]
pub enum Req {
    RunMain { argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String> },
    RunExec { argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String>, detach: bool },
    /// Instance-level signal: `sandlock-init` delivers `signum` to every
    /// registered child's process group (group-first killpg + pidfd
    /// complement). No pid payload — see the module docs.
    Signal { signum: i32 },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "lowercase")]
pub enum Resp {
    Started { pid: i32 },
    Exited { pid: i32, code: Option<i32>, signal: Option<i32> },
    Err { msg: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn req_roundtrip() {
        let r = Req::RunExec { argv: vec!["sh".into()], env: vec![("A".into(),"1".into())], cwd: Some("/".into()), detach: false };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("runexec"));
        assert!(matches!(serde_json::from_str::<Req>(&j).unwrap(), Req::RunExec { .. }));
    }
    #[test]
    fn resp_roundtrip() {
        let r = Resp::Exited { pid: 7, code: Some(0), signal: None };
        let j = serde_json::to_string(&r).unwrap();
        assert!(matches!(serde_json::from_str::<Resp>(&j).unwrap(), Resp::Exited { pid: 7, .. }));
    }
    #[test]
    fn signal_req_roundtrip() {
        let j = r#"{"req":"signal","signum":9}"#;
        match serde_json::from_str::<Req>(j).unwrap() {
            Req::Signal { signum } => assert_eq!(signum, libc::SIGKILL),
            other => panic!("expected Req::Signal, got {:?}", other),
        }
        // No arbitrary-pid variant may ever serialize onto this channel: a
        // pid-bearing frame must either stay instance-level (unknown fields
        // are ignored) or fail to parse — never become a per-pid verb.
        let pid_frame = r#"{"req":"signal","pid":424242,"signum":9}"#;
        match serde_json::from_str::<Req>(pid_frame) {
            Ok(Req::Signal { signum }) => assert_eq!(signum, libc::SIGKILL),
            Ok(other) => panic!("expected Req::Signal, got {:?}", other),
            Err(_) => {}
        }
    }
}
