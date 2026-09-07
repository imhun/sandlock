//! Root-mode foreign-uid acceptance (fork-plan F2b.3).
//!
//! The core route-B claim is: *a `sandlock-supervise` process running as a
//! foreign non-root host uid X is fully functional* — it builds a
//! `SandboxInstance` from the full-field policy, launches and mediates the
//! workload (Landlock/seccomp-notif, DNS gateway, inbound port mapping), and
//! serves instance-level verbs to a worker running as a *different* uid
//! (65534) over both control transports.
//!
//! A non-root test process cannot `setuid` to a second host uid (no
//! CAP_SETUID), so this acceptance runs in the **root container phase**:
//! `scripts/test-all.sh --supervise-root` executes this target as root in
//! the same privileged container as the oci root gate, and the test spawns
//! supervise under `setpriv --reuid=65533` (uid X) while the worker runs
//! under `setpriv --reuid=65534`.  These are real kernel identities — the
//! `SO_PEERCRED` allowlist, the DAC-visible file ownership, and the
//! mediator-uid identity are all genuine.
//!
//! There is deliberately NO soft skip here: if this target is executed as a
//! non-root process it fails loudly (the runner only invokes it in the root
//! phase), and every assertion below is exact.  Uid X = 65533 is chosen
//! outside every reserved/meaningful id: not 0, not the 1–999 system range,
//! not 65534 (`nobody`/overflowuid/worker), and not the container's mapped
//! user ids.

use std::io::{BufRead, BufReader, Read};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const UID_X: u32 = 65533;
const UID_WORKER: u32 = 65534;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-supervise")
}

fn repo_tmp_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.join("../../tmp");
    std::fs::create_dir_all(&dir).expect("create repo tmp dir");
    // Canonicalize: registered unix socket paths are SUN_LEN-bounded (108
    // bytes), and a non-normalized CARGO_MANIFEST_DIR path (`…/crates/…
    // /../../tmp/…`) wastes ~30 bytes on the literal `..` components.
    std::fs::canonicalize(&dir).expect("canonicalize repo tmp dir")
}

fn root_phase_env_check() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "the supervise_root target must run as root (scripts/test-all.sh \
         --supervise-root in the privileged container); a non-root run fails \
         loudly — there is no soft skip for the foreign-uid acceptance"
    );
    assert!(
        Command::new("setpriv")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        "setpriv (util-linux) must be present in the root container phase"
    );
    assert!(
        Command::new("python3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        "python3 must be present (workload + worker probes)"
    );
}

fn base_read_paths() -> Vec<String> {
    let mut paths = vec![
        "/usr".to_string(),
        "/lib".to_string(),
        "/bin".to_string(),
        "/etc".to_string(),
        "/proc".to_string(),
        "/dev".to_string(),
    ];
    if Path::new("/lib64").exists() {
        paths.push("/lib64".to_string());
    }
    paths
}

fn write_shared(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write shared test file");
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
}

fn chmod_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))
        .expect("chmod shared dir");
}

fn wait_until(deadline: Instant, what: &str, mut predicate: impl FnMut() -> bool) {
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_child_exit(child: &mut Child, timeout: Duration, what: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait child") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what} to exit"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn spawn_setpriv(
    uid: u32,
    args: &[&str],
    envs: &[(&str, &str)],
    stdout: Stdio,
    stderr: Stdio,
) -> Child {
    let mut cmd = Command::new("setpriv");
    cmd.args([
        "--reuid",
        &uid.to_string(),
        "--regid",
        &uid.to_string(),
        "--clear-groups",
        "--",
    ])
    .args(args)
    .stdout(stdout)
    .stderr(stderr);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn setpriv child")
}

/// Allocate a free TCP port (bind :0, read it, drop the listener).
fn alloc_ephemeral_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

/// Allocate a free host port in the reserved inbound range (50005+).
fn alloc_host_port_in_range(min: u16) -> u16 {
    for port in min..=min + 200 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("could not allocate a host port in {min}..={}", min + 200);
}

/// All pids whose real uid is `uid` (read from /proc/<pid>/status Uid line).
fn processes_with_uid(uid: u32) -> Vec<i32> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let real_uid = status.lines().find_map(|line| {
            let rest = line.strip_prefix("Uid:")?;
            rest.split_whitespace().next()?.parse::<u32>().ok()
        });
        if real_uid == Some(uid) {
            found.push(pid);
        }
    }
    found
}

/// A `*.d` sandbox-state dir under `root` (instance control dirs / registered
/// channel dirs) — anything left after shutdown is residue.
fn state_dirs_under(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".d"))
                .unwrap_or(false)
        })
        .collect()
}

/// `connect(127.0.0.1:port)` result — `Some(errno)` on refusal/failure,
/// `None` when a connection was established (dropped immediately).
fn connect_errno(port: u16) -> Option<i32> {
    match std::net::TcpStream::connect(("127.0.0.1", port)) {
        Ok(stream) => {
            drop(stream);
            None
        }
        Err(e) => Some(e.raw_os_error().unwrap_or(-1)),
    }
}

/// FUP-11d: how long the harness worker keeps retrying `connect()` while it
/// waits for a registered slot's socket to appear.  This is a *start-up*
/// budget, not a per-request one: the slot binds before launching the
/// instance, so the retry only has to ride out slot start-up (120 s is far
/// above the slowest bind observed on this gate and still fails a genuinely
/// dead slot inside one suite step).
const REGISTERED_CONNECT_RETRY: Duration = Duration::from_secs(120);

/// FUP-11d: per-socket send/receive deadline once the worker is connected —
/// deliberately far shorter than [`REGISTERED_CONNECT_RETRY`].  A slot that
/// accepted a connection and then does not answer a verb within 30 s is
/// wedged, and that has to surface as a named timeout on the verb that hung
/// instead of quietly eating the remaining connect budget.  The asymmetry is
/// the point (audit item FUP-11: "first-verb recv timeout vs connect retry").
const VERB_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// FUP-11c: how many refused (wrong-token) connections the registered-path
/// acceptance drives through the slot's accept loop.  Must exceed
/// `AbnormalEndLog::REPORT_EVERY` so the throttle window itself is exercised,
/// and the slot's stderr is pinned to exactly two lines (the naming first
/// abnormal end + the one at the window boundary).
const REFUSED_FLOOD_CONNECTIONS: usize = 300;

/// FUP-11c: the token the flood connections present (never the slot's real
/// channel token, so every one of them is a genuine token refusal).
const REFUSED_TOKEN: &str = "flood-wrong-token";

/// The workload probe: runs INSIDE the uid-X sandbox and writes tagged
/// evidence lines for every acceptance item (Landlock deny, seccomp deny,
/// DNS gateway, inbound mapping), then parks until shutdown kills it.
const WORKLOAD_PROBE: &str = r#"import errno, os, socket, threading, time

ev = os.environ["SUPERVISE_EVIDENCE"]
port = int(os.environ["SUPERVISE_SANDBOX_PORT"])
host = os.environ["SUPERVISE_DNS_HOST"]

def note(tag, value):
    with open(ev, "a") as f:
        f.write(tag + "=" + value + "\n")

def fail(code, tag, value):
    note(tag, value)
    os._exit(code)

# 1. Landlock: reading a denied path must fail (EACCES).
try:
    open("/etc/shadow", "rb").close()
    fail(10, "fs_denied", "BAD:read-succeeded")
except OSError as e:
    if e.errno in (errno.EACCES, errno.EPERM):
        note("fs_denied", "ok")
    else:
        fail(10, "fs_denied", "BAD:errno=%s" % e.errno)

# 2. seccomp deny: chmod is on extra_deny_syscalls and must fail (EPERM).
try:
    os.chmod(ev, 0o600)
    fail(11, "syscall_deny", "BAD:chmod-succeeded")
except OSError as e:
    if e.errno in (errno.EACCES, errno.EPERM):
        note("syscall_deny", "ok")
    else:
        fail(11, "syscall_deny", "BAD:errno=%s" % e.errno)

# 3. DNS gateway: the wildcard subdomain must resolve to a synthetic IP
#    through the sandbox's own gateway (supervisor-mediated).
try:
    ip = socket.gethostbyname(host)
except OSError as e:
    fail(12, "dns", "BAD:%s" % e)
note("dns", "synthetic:%s" % ip)

# 4. Inbound mapping: bind the mapped sandbox port inside the netns; the
#    external worker reaches it through the supervisor's host listener.
served = threading.Event()

def server():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(8)
        note("inbound_server", "ready")
        conn, _ = s.accept()
        data = conn.recv(4)
        if data == b"ping":
            conn.sendall(b"PONG")
        conn.close()
        served.set()
    except OSError as e:
        note("inbound", "BAD:%s" % e)

t = threading.Thread(target=server)
t.start()
if served.wait(60):
    note("inbound", "served")
else:
    note("inbound", "BAD:timeout")
note("probe", "done")
while True:
    time.sleep(3600)
"#;

/// The control worker: runs as uid 65534 and drives the instance verbs plus
/// the external inbound connection.  Prints one JSON report line on stdout.
const WORKER_SCRIPT: &str = r#"import json, os, socket, struct, sys, time

cfg = json.load(open(sys.argv[1]))
report = {"worker_uid": os.geteuid()}

def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def frame(s, name, token, args):
    body = json.dumps({"v": 1, "verb": name, "token": token, "args": args or {}}).encode()
    s.sendall(struct.pack(">I", len(body)) + body)
    length = struct.unpack(">I", recv_exact(s, 4))[0]
    return json.loads(recv_exact(s, length))

def expect_ok(resp, what):
    if not resp.get("ok"):
        raise AssertionError("%s refused: %r" % (what, resp))
    return resp

def open_fd_transport(cfg):
    s = socket.socket(fileno=cfg["fd"])
    s.settimeout(cfg["verb_timeout_s"])
    return s

def open_registered_transport(cfg):
    # FUP-11d: the connect budget (waiting for the slot's socket to appear)
    # and the per-verb I/O budget are deliberately asymmetric — see the Rust
    # constants that feed these two numbers.
    deadline = time.time() + cfg["connect_retry_s"]
    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(cfg["verb_timeout_s"])
            s.connect(cfg["sock"])
            return s
        except OSError:
            s.close()
            if time.time() >= deadline:
                raise
            time.sleep(0.2)

def one_verb(transport, cfg, name, args=None):
    # registered path: one connection per verb
    if transport == "registered":
        s = open_registered_transport(cfg)
        try:
            return expect_ok(frame(s, name, cfg["token"], args), name)
        finally:
            s.close()
    else:
        raise AssertionError("persistent transports use drive()")

def drive(cfg):
    transport = cfg["transport"]
    token = cfg.get("token", "")

    if transport == "registered":
        resp = one_verb(transport, cfg, "config")
        report["config_ok"] = True
        resp = one_verb(transport, cfg, "run")
        report["run_pid"] = resp["data"]["pid"]

        deadline = time.time() + 90
        settled = False
        prev = None
        while time.time() < deadline:
            resp = one_verb(transport, cfg, "stats")
            d = resp["data"]
            if d.get("instance_state") == "Live" and d.get("children_live") == 1:
                # "对账一致" (reconciler consistent): the F1.4 deviation must
                # be STABLE across two consecutive samples.  A plain single
                # process settles at 0; a threaded workload legitimately
                # holds one extra supervisor watcher slot (threads register
                # as fork events), so the acceptance pins stability + the M0
                # child truth instead of a workload-specific magic number.
                if prev is not None and prev == d:
                    report["stats"] = d
                    report["stats_stable"] = True
                    settled = True
                    break
                prev = d
            time.sleep(0.3)
        if not settled:
            try:
                ev = open(cfg["evidence"]).read()
            except OSError:
                ev = "<unreadable>"
            raise AssertionError(
                "stats never settled to a stable live snapshot: last=%r evidence=%r" % (d, ev))

        deadline = time.time() + 90
        live = False
        while time.time() < deadline:
            resp = one_verb(transport, cfg, "ports")
            for entry in resp["data"]["inbound"]:
                if entry["host_port"] == cfg["host_port"] and entry["live"]:
                    report["ports"] = entry
                    live = True
                    break
            if live:
                break
            time.sleep(0.2)
        if not live:
            raise AssertionError("host inbound listener never became live")

        # External MCP-style round-trip through the mapped host port.
        deadline = time.time() + 30
        pong = False
        while time.time() < deadline:
            try:
                c = socket.create_connection(("127.0.0.1", cfg["host_port"]), timeout=5)
                c.settimeout(5)
                c.sendall(b"ping")
                if recv_exact(c, 4) == b"PONG":
                    pong = True
                c.close()
                if pong:
                    break
            except OSError:
                time.sleep(0.2)
        if not pong:
            raise AssertionError("inbound PONG round-trip failed")
        report["inbound_roundtrip"] = "PONG"

        # Wait for the workload's own evidence before ending the generation.
        deadline = time.time() + 60
        complete = False
        while time.time() < deadline:
            try:
                lines = set(open(cfg["evidence"]).read().splitlines())
            except OSError:
                lines = set()
            required = {"fs_denied=ok", "syscall_deny=ok", "inbound=served", "probe=done"}
            if required.issubset(lines) and any(l.startswith("dns=synthetic:") for l in lines):
                complete = True
                break
            time.sleep(0.2)
        if not complete:
            raise AssertionError("workload evidence never completed")

        # FUP-11c: a refused-connection flood must not become a log flood.
        # Every one of these connections is an abnormal end for the slot; the
        # Rust side pins that the slot's stderr holds only the naming first
        # line plus one line per throttle window (not 300 lines).
        refused = 0
        for _ in range(cfg["refused_flood"]):
            s = open_registered_transport(cfg)
            try:
                resp = frame(s, "config", cfg["refused_token"], {})
            finally:
                s.close()
            if not resp.get("ok"):
                refused += 1
        if refused != cfg["refused_flood"]:
            raise AssertionError(
                "expected all %d flood connections refused, got %d"
                % (cfg["refused_flood"], refused))
        report["refused_flood"] = refused

        resp = one_verb(transport, cfg, "shutdown")
        report["shutdown_ok"] = True

    else:
        s = open_fd_transport(cfg)
        try:
            resp = expect_ok(frame(s, "config", token, {}), "config")
            report["config_ok"] = True
            resp = expect_ok(frame(s, "run", token, {}), "run")
            report["run_pid"] = resp["data"]["pid"]
            deadline = time.time() + 60
            settled = False
            while time.time() < deadline:
                resp = expect_ok(frame(s, "stats", token, {}), "stats")
                d = resp["data"]
                if d.get("instance_state") == "Live" and d.get("children_live") == 1 \
                        and d.get("proc_count_vs_live") == 0:
                    report["stats"] = d
                    settled = True
                    break
                time.sleep(0.2)
            if not settled:
                raise AssertionError("fd stats never settled: last=%r" % (d,))
            resp = expect_ok(frame(s, "ports", token, {}), "ports")
            report["ports_empty"] = (resp["data"]["inbound"] == [])
            resp = expect_ok(frame(s, "shutdown", token, {}), "shutdown")
            report["shutdown_ok"] = True
        finally:
            s.close()

drive(cfg)
print(json.dumps(report))
"#;

fn write_evidence_and_worker_config(
    base: &Path,
    mode: &str,
    sock: Option<&str>,
    fd: Option<RawFd>,
    token: &str,
    host_port: u16,
    evidence: &Path,
) -> PathBuf {
    let config = serde_json::json!({
        "transport": mode,
        "sock": sock,
        "fd": fd,
        "token": token,
        "host_port": host_port,
        "evidence": evidence.to_string_lossy(),
        // FUP-11d: the budgets live in Rust and reach the python worker
        // through the config, so harness and comments cannot drift apart.
        "connect_retry_s": REGISTERED_CONNECT_RETRY.as_secs(),
        "verb_timeout_s": VERB_IO_TIMEOUT.as_secs(),
        "refused_flood": REFUSED_FLOOD_CONNECTIONS,
        "refused_token": REFUSED_TOKEN,
    });
    let cfg_path = base.join("worker-config.json");
    write_shared(&cfg_path, &config.to_string());
    cfg_path
}

fn read_worker_report(child: &mut Child) -> serde_json::Value {
    let mut stdout = String::new();
    if let Some(ref mut pipe) = child.stdout {
        pipe.read_to_string(&mut stdout)
            .expect("read worker stdout");
    }
    let line = stdout.lines().last().expect("worker printed a report line");
    serde_json::from_str(line).expect("worker report is JSON")
}

fn read_evidence_lines(path: &Path) -> Vec<String> {
    let file = std::fs::File::open(path).expect("open evidence file");
    BufReader::new(file)
        .lines()
        .map(|l| l.expect("evidence line"))
        .collect()
}

fn is_synthetic(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let n = u32::from(ip);
    (0x0afa_0002..=0x0afa_fffe).contains(&n)
}

/// Fork-plan F2b.3 core acceptance — registered path transport:
///
/// supervise runs as uid X = 65533 (`setpriv`), binds a registered channel
/// under the shared ctl root, builds and launches the sandbox instance, and
/// serves a worker that runs as uid 65534.  The worker asserts config/run/
/// stats/ports over the real cross-uid channel, completes an external inbound
/// round-trip through the mapped host listener, waits for the workload's
/// mediation/DNS evidence, and ends the generation with a shutdown verb.
/// The root side then asserts clean exit, exact evidence, and no uid-X
/// residue (processes, listeners, sockets, state dirs).
#[test]
fn test_supervisor_as_foreign_uid_is_fully_functional() {
    root_phase_env_check();
    let base = repo_tmp_dir().join(format!("supervise-root-func-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create root-func base");
    chmod_dir(&base);
    let ctl_root = base.join("ctl");
    std::fs::create_dir_all(&ctl_root).expect("create ctl root");
    chmod_dir(&ctl_root);
    let evidence_dir = base.join("evidence");
    std::fs::create_dir_all(&evidence_dir).expect("create evidence dir");
    chmod_dir(&evidence_dir);
    let evidence = evidence_dir.join("evidence.txt");
    let probe = base.join("probe.py");
    write_shared(&probe, WORKLOAD_PROBE);

    let sandbox_port = alloc_ephemeral_port();
    let host_port = alloc_host_port_in_range(50005);
    let name = format!("supervise-root-func-{}", std::process::id());
    let token = format!("{:064x}", std::process::id() as u64);

    let mut readable = base_read_paths();
    readable.push(base.to_string_lossy().into_owned());
    let policy = serde_json::json!({
        "fs_readable": readable,
        "fs_writable": [evidence_dir.to_string_lossy()],
        "fs_denied": ["/etc/shadow"],
        "extra_deny_syscalls": ["chmod"],
        "net_isolation": true,
        "net_allow": [
            "*.example.com:443",
            format!("127.0.0.1:{sandbox_port}")
        ],
        "net_allow_bind": [sandbox_port],
        "port_mappings": {host_port.to_string(): sandbox_port},
        "env": {
            "SUPERVISE_EVIDENCE": evidence.to_string_lossy(),
            "SUPERVISE_SANDBOX_PORT": sandbox_port.to_string(),
            "SUPERVISE_DNS_HOST": "api.example.com",
        },
    })
    .to_string();
    let policy_path = base.join("policy.json");
    write_shared(&policy_path, &policy);

    let program = serde_json::json!({
        "argv": ["python3", "-B", probe.to_string_lossy()]
    })
    .to_string();
    let program_path = base.join("program.json");
    write_shared(&program_path, &program);

    let worker_script = base.join("worker.py");
    write_shared(&worker_script, WORKER_SCRIPT);

    let sock_path = PathBuf::from(format!(
        "{}-registry/{}.d/control.sock",
        ctl_root.to_string_lossy().trim_end_matches('/'),
        sandlock_core::control::fnv1a_hex(&name),
    ));

    // Supervise as uid X: registered path, worker allowlist = 65534.
    let mut supervise = spawn_setpriv(
        UID_X,
        &[
            bin(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--uid",
            &UID_X.to_string(),
            "--serve-path",
            &name,
            "--token",
            &token,
            "--peer-uid",
            &UID_WORKER.to_string(),
            "--program",
            program_path.to_str().unwrap(),
        ],
        &[("SANDBOX_CTL_ROOT", ctl_root.to_str().unwrap())],
        Stdio::null(),
        Stdio::piped(),
    );

    // Wait for the slot's registered socket, then run the worker as 65534.
    let socket_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if sock_path.exists() {
            break;
        }
        if let Some(status) = supervise.try_wait().expect("try_wait supervise") {
            let mut err = String::new();
            if let Some(ref mut pipe) = supervise.stderr {
                let _ = pipe.read_to_string(&mut err);
            }
            panic!(
                "supervise exited (status {status}) before binding the registered \
                 socket {sock_path:?}; stderr: {err}"
            );
        }
        assert!(
            Instant::now() < socket_deadline,
            "timed out waiting for registered slot socket {sock_path:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let worker_cfg = write_evidence_and_worker_config(
        &base,
        "registered",
        Some(sock_path.to_str().unwrap()),
        None,
        &token,
        host_port,
        &evidence,
    );
    let mut worker = spawn_setpriv(
        UID_WORKER,
        &[
            "python3",
            "-B",
            worker_script.to_str().unwrap(),
            worker_cfg.to_str().unwrap(),
        ],
        &[("SANDBOX_CTL_ROOT", ctl_root.to_str().unwrap())],
        Stdio::piped(),
        Stdio::piped(),
    );
    let worker_status =
        wait_child_exit(&mut worker, Duration::from_secs(180), "foreign-uid worker");
    let worker_err = {
        let mut err = String::new();
        if let Some(ref mut pipe) = worker.stderr {
            let _ = pipe.read_to_string(&mut err);
        }
        err
    };
    assert!(
        worker_status.success(),
        "foreign-uid worker must exit 0; stderr: {worker_err}"
    );
    let worker_report = read_worker_report(&mut worker);
    assert_eq!(
        worker_report["worker_uid"], UID_WORKER,
        "the worker must genuinely run as 65534: {worker_report}"
    );
    assert_eq!(worker_report["config_ok"], serde_json::Value::Bool(true));
    assert!(
        worker_report["run_pid"].as_i64().is_some(),
        "run must report the instance pid: {worker_report}"
    );
    assert_eq!(
        worker_report["stats"]["instance_state"], "Live",
        "stats: {worker_report}"
    );
    assert_eq!(
        worker_report["stats"]["children_live"], 1,
        "stats: {worker_report}"
    );
    assert_eq!(
        worker_report["stats_stable"],
        serde_json::Value::Bool(true),
        "reconciler must settle to a stable snapshot (对账一致): {worker_report}"
    );
    // FUP-11e (root sibling of the non-root path case): the settle point is
    // the reconciled snapshot, so the drift counter itself must be zero.
    assert_eq!(
        worker_report["stats"]["proc_count_vs_live"], 0,
        "a settled snapshot must show zero accounting drift: {worker_report}"
    );
    assert_eq!(
        worker_report["ports"]["host_port"], host_port,
        "ports must report the live mapped host listener: {worker_report}"
    );
    assert_eq!(
        worker_report["ports"]["live"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(worker_report["inbound_roundtrip"], "PONG");
    assert_eq!(
        worker_report["shutdown_ok"],
        serde_json::Value::Bool(true),
        "shutdown verb: {worker_report}"
    );
    // FUP-11c: every flood connection really was refused (so the slot really
    // saw that many abnormal ends before the log assertion below).
    assert_eq!(
        worker_report["refused_flood"],
        REFUSED_FLOOD_CONNECTIONS as u64,
        "the worker must have driven the whole refused flood: {worker_report}"
    );

    let supervise_status = wait_child_exit(
        &mut supervise,
        Duration::from_secs(120),
        "foreign-uid supervise exit",
    );
    let supervise_err = {
        let mut err = String::new();
        if let Some(ref mut pipe) = supervise.stderr {
            let _ = pipe.read_to_string(&mut err);
        }
        err
    };
    assert!(
        supervise_status.success(),
        "foreign-uid generation must exit 0 after shutdown; stderr: {supervise_err}"
    );
    // FUP-11c: the worker drove `REFUSED_FLOOD_CONNECTIONS` refused
    // connections through this slot's accept loop.  Every one of them is an
    // abnormal end, yet the slot must print only the naming first line plus
    // one line at the throttle-window boundary — an unthrottled
    // `eprintln!`-per-connection would have printed 300 here.
    assert!(
        REFUSED_FLOOD_CONNECTIONS
            > sandlock_supervise::serve::AbnormalEndLog::REPORT_EVERY as usize,
        "the flood must cross a throttle window to prove the second line"
    );
    let logged: Vec<String> = supervise_err.lines().map(|line| line.to_string()).collect();
    let expected_log: Vec<String> = vec![
        sandlock_supervise::serve::registered_abnormal_end_line(1),
        sandlock_supervise::serve::registered_abnormal_end_line(
            sandlock_supervise::serve::AbnormalEndLog::REPORT_EVERY,
        ),
    ];
    assert_eq!(
        logged,
        expected_log,
        "the slot must throttle its abnormal-end log (FUP-11c), got \
         {} line(s)",
        logged.len()
    );

    // Exact evidence lines from the workload inside the uid-X sandbox.
    let lines = read_evidence_lines(&evidence);
    let set: std::collections::BTreeSet<&str> = lines.iter().map(|s| s.as_str()).collect();
    let mut expected: std::collections::BTreeSet<&str> = [
        "fs_denied=ok",
        "syscall_deny=ok",
        "inbound_server=ready",
        "inbound=served",
        "probe=done",
    ]
    .into_iter()
    .collect();
    let dns_line = lines
        .iter()
        .find(|l| l.starts_with("dns=synthetic:"))
        .unwrap_or_else(|| panic!("evidence must contain the synthetic DNS line, got: {lines:?}"));
    let synthetic_ip = dns_line.trim_start_matches("dns=synthetic:");
    assert!(
        is_synthetic(synthetic_ip),
        "synthetic IP expected, got: {dns_line}"
    );
    expected.insert(dns_line.as_str());
    assert_eq!(
        set, expected,
        "evidence lines must be exactly the mediated acceptance set (no BAD, \
         no extras); full file: {lines:?}"
    );

    // No residue in the uid-X name: host listener closed, channel socket
    // gone, no state dirs, no uid-65533 processes.
    assert!(
        connect_errno(host_port).is_some(),
        "the mapped host listener must be closed after the generation ends"
    );
    assert!(
        !sock_path.exists(),
        "the registered slot socket must be cleaned up"
    );
    let registry_root = PathBuf::from(format!(
        "{}-registry",
        ctl_root.to_string_lossy().trim_end_matches('/')
    ));
    assert!(
        state_dirs_under(&registry_root).is_empty(),
        "no registered channel dirs may survive: {:?}",
        state_dirs_under(&registry_root)
    );
    assert!(
        state_dirs_under(&ctl_root).is_empty(),
        "no instance control dirs may survive shutdown: {:?}",
        state_dirs_under(&ctl_root)
    );
    wait_until(
        Instant::now() + Duration::from_secs(10),
        "uid-X processes to exit",
        || processes_with_uid(UID_X).is_empty(),
    );
    assert!(
        processes_with_uid(UID_X).is_empty(),
        "no process may survive under uid {UID_X}: {:?}",
        processes_with_uid(UID_X)
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// FUP-11d: the harness budgets must keep their documented shape.  A wedged
/// slot that already accepted a connection must fail a verb long before the
/// connect-retry budget for a slot that never appeared runs out, and the
/// refused flood must be long enough to cross a log throttle window (otherwise
/// the FUP-11c pin above would pass even without throttling).
#[test]
fn test_harness_timeouts_and_flood_keep_their_contract() {
    assert_eq!(
        REGISTERED_CONNECT_RETRY,
        Duration::from_secs(120),
        "the slot-bind retry budget is documented as 120 s"
    );
    assert_eq!(
        VERB_IO_TIMEOUT,
        Duration::from_secs(30),
        "the per-verb send/receive deadline is documented as 30 s"
    );
    assert!(
        VERB_IO_TIMEOUT < REGISTERED_CONNECT_RETRY,
        "a verb must fail faster than the whole slot wait"
    );
    assert!(
        REFUSED_FLOOD_CONNECTIONS
            > sandlock_supervise::serve::AbnormalEndLog::REPORT_EVERY as usize,
        "the flood must cross a throttle window to prove the second log line"
    );
}

/// FUP-03 exit-order harness: a worker that closes the fd control channel
/// FIRST while a workload is live (no `shutdown` verb) is an abnormal
/// generation end. Supervise (foreign uid X) must exit non-zero AND leave no
/// uid-X process behind — live or zombie — after its synchronous teardown.
#[test]
fn test_supervisor_as_foreign_uid_fd_handoff_worker_close_first_leaves_no_residue() {
    root_phase_env_check();
    let base = repo_tmp_dir().join(format!("supervise-root-fd-exitorder-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create root exit-order base");
    chmod_dir(&base);
    let ctl_root = base.join("ctl");
    std::fs::create_dir_all(&ctl_root).expect("create ctl root");
    chmod_dir(&ctl_root);
    let policy_path = base.join("policy.json");
    let mut readable = base_read_paths();
    readable.push(base.to_string_lossy().into_owned());
    write_shared(
        &policy_path,
        &serde_json::json!({
            "fs_readable": readable,
            "fs_writable": [base.to_string_lossy()],
        })
        .to_string(),
    );
    let program_path = base.join("program.json");
    write_shared(
        &program_path,
        &serde_json::json!({ "argv": ["/bin/sleep", "300"] }).to_string(),
    );

    let (mut worker, server_stream) =
        std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let server_fd = server_stream.as_raw_fd();
    let mut cmd = Command::new("setpriv");
    cmd.args([
        "--reuid",
        &UID_X.to_string(),
        "--regid",
        &UID_X.to_string(),
        "--clear-groups",
        "--",
        bin(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--program",
        program_path.to_str().unwrap(),
        "--uid",
        &UID_X.to_string(),
        "--control-fd",
        &server_fd.to_string(),
        "--serve",
    ])
    .env("SANDBOX_CTL_ROOT", &ctl_root)
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            // FUP-06: only the server end belongs to supervise.
            let flags = libc::fcntl(server_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(server_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut supervise = cmd.spawn().expect("spawn fd-mode supervise");
    drop(server_stream);

    use std::io::{Read, Write};
    let body = serde_json::json!({ "v": 1, "verb": "run", "args": {} });
    let bytes = serde_json::to_vec(&body).expect("serialize run frame");
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(&bytes);
    worker.write_all(&frame).expect("write run frame");

    let mut len_buf = [0u8; 4];
    worker
        .read_exact(&mut len_buf)
        .expect("read run response length");
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    worker.read_exact(&mut resp).expect("read run response");
    let resp: serde_json::Value = serde_json::from_slice(&resp).expect("run response JSON");
    assert_eq!(
        resp["ok"],
        serde_json::Value::Bool(true),
        "run must start the workload: {resp:?}"
    );

    // Worker closes first, without a shutdown verb: abnormal generation end.
    drop(worker);
    let status = wait_child_exit(
        &mut supervise,
        Duration::from_secs(90),
        "exit-order supervise",
    );
    let err = {
        let mut text = String::new();
        if let Some(ref mut pipe) = supervise.stderr {
            let _ = pipe.read_to_string(&mut text);
        }
        text
    };
    assert!(
        !status.success(),
        "worker-close-first must exit non-zero; stderr: {err}"
    );
    let first = err.lines().next().unwrap_or_default();
    assert!(
        first.starts_with("sandlock-supervise: control channel ended abnormally ("),
        "the abnormal end must be named first, got: {first}"
    );
    wait_until(
        Instant::now() + Duration::from_secs(10),
        "exit-order uid-X processes to exit",
        || processes_with_uid(UID_X).is_empty(),
    );
    assert!(
        processes_with_uid(UID_X).is_empty(),
        "worker-close-first must leave no live or zombie uid-X process: {:?}",
        processes_with_uid(UID_X)
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// Mechanism-level fd-handoff coverage under the same genuine identities:
/// supervise (uid X) serves the handed-over socketpair end; the worker end
/// is held by a real uid-65534 process.  The fd is the credential, so this
/// test exercises the foreign-uid instance lifecycle over transport 1
/// (config/run/stats/ports/shutdown) plus the no-residue exit.
#[test]
fn test_supervisor_as_foreign_uid_fd_handoff_serves_worker() {
    root_phase_env_check();
    let base = repo_tmp_dir().join(format!("supervise-root-fd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create root-fd base");
    chmod_dir(&base);
    let ctl_root = base.join("ctl");
    std::fs::create_dir_all(&ctl_root).expect("create ctl root");
    chmod_dir(&ctl_root);

    let mut readable = base_read_paths();
    readable.push(base.to_string_lossy().into_owned());
    let policy = serde_json::json!({
        "fs_readable": readable,
        "fs_writable": [base.to_string_lossy()],
    })
    .to_string();
    let policy_path = base.join("policy.json");
    write_shared(&policy_path, &policy);
    let program = serde_json::json!({ "argv": ["/bin/sleep", "300"] }).to_string();
    let program_path = base.join("program.json");
    write_shared(&program_path, &program);

    let token = format!("fd-{:064x}", std::process::id() as u64);
    let (worker_stream, server_stream) =
        std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let worker_fd = worker_stream.as_raw_fd();
    let server_fd = server_stream.as_raw_fd();

    // Supervise as uid X with the server end of the socketpair.
    let mut cmd = Command::new("setpriv");
    cmd.args([
        "--reuid",
        &UID_X.to_string(),
        "--regid",
        &UID_X.to_string(),
        "--clear-groups",
        "--",
        bin(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--uid",
        &UID_X.to_string(),
        "--control-fd",
        &server_fd.to_string(),
        "--token",
        &token,
        "--program",
        program_path.to_str().unwrap(),
        "--serve",
    ])
    .env("SANDBOX_CTL_ROOT", &ctl_root)
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            // FUP-06: only the server end belongs to supervise. The worker
            // end stays CLOEXEC and closes at this exec, so supervise cannot
            // hold its own write end open and mask EOF semantics.
            let flags = libc::fcntl(server_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(server_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut supervise = cmd.spawn().expect("spawn fd-mode supervise");
    drop(server_stream);

    // Worker as uid 65534 with the other end of the socketpair.
    let worker_script = base.join("worker.py");
    write_shared(&worker_script, WORKER_SCRIPT);
    let worker_cfg = write_evidence_and_worker_config(
        &base,
        "fd",
        None,
        Some(worker_fd),
        &token,
        0,
        &base.join("unused-evidence.txt"),
    );
    // Worker as uid 65534 with the other end of the socketpair: the fd must
    // survive BOTH execs (setpriv → python), so clear FD_CLOEXEC in the
    // child right before the first exec.
    let mut cmd = Command::new("setpriv");
    cmd.args([
        "--reuid",
        &UID_WORKER.to_string(),
        "--regid",
        &UID_WORKER.to_string(),
        "--clear-groups",
        "--",
        "python3",
        "-B",
        worker_script.to_str().unwrap(),
        worker_cfg.to_str().unwrap(),
    ])
    .env("SANDBOX_CTL_ROOT", &ctl_root)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            let flags = libc::fcntl(worker_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(worker_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut worker = cmd.spawn().expect("spawn fd worker");
    // The parent's copy of the worker end can close now: the worker child
    // inherited its own descriptor at exec.
    drop(worker_stream);

    let worker_status = wait_child_exit(&mut worker, Duration::from_secs(120), "fd worker");
    let worker_err = {
        let mut err = String::new();
        if let Some(ref mut pipe) = worker.stderr {
            let _ = pipe.read_to_string(&mut err);
        }
        err
    };
    assert!(
        worker_status.success(),
        "fd worker must exit 0; stderr: {worker_err}"
    );
    let worker_report = read_worker_report(&mut worker);
    assert_eq!(worker_report["worker_uid"], UID_WORKER);
    assert_eq!(worker_report["config_ok"], serde_json::Value::Bool(true));
    assert!(worker_report["run_pid"].as_i64().is_some());
    assert_eq!(worker_report["stats"]["instance_state"], "Live");
    assert_eq!(worker_report["stats"]["children_live"], 1);
    assert_eq!(
        worker_report["stats"]["proc_count_vs_live"], 0,
        "fd stats: {worker_report}"
    );
    assert_eq!(worker_report["ports_empty"], serde_json::Value::Bool(true));
    assert_eq!(worker_report["shutdown_ok"], serde_json::Value::Bool(true));

    let supervise_status =
        wait_child_exit(&mut supervise, Duration::from_secs(90), "fd supervise exit");
    let supervise_err = {
        let mut err = String::new();
        if let Some(ref mut pipe) = supervise.stderr {
            let _ = pipe.read_to_string(&mut err);
        }
        err
    };
    assert!(
        supervise_status.success(),
        "fd foreign-uid generation must exit 0; stderr: {supervise_err}"
    );
    wait_until(
        Instant::now() + Duration::from_secs(10),
        "fd uid-X processes to exit",
        || processes_with_uid(UID_X).is_empty(),
    );
    assert!(
        processes_with_uid(UID_X).is_empty(),
        "no process may survive under uid {UID_X}: {:?}",
        processes_with_uid(UID_X)
    );
    let _ = std::fs::remove_dir_all(&base);
}
