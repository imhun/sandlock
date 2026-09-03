# Upstream PR: unprivileged domain-wildcard networking + header inject / host mask

> Branch: `imhun/sandlock` → `upstream-pr/netns-free-clean` (base:
> `multikernel/sandlock` `main` @ `f6a3e39`). Purely unprivileged — no
> `CLONE_NEWNET` / veth / `CAP_NET_ADMIN`.

## Summary

Two unprivileged network features, implemented entirely in the supervisor's
seccomp user-notification path (no per-sandbox netns, no privileges beyond what
sandlock already requires):

1. **Domain-suffix wildcards in `net_allow`** — `*.example.com[:port]` matches
   any subdomain at connect/send time. The sandbox resolves wildcard subdomains
   through a per-sandbox loopback DNS gateway (`127.0.1.x:53`) that answers A
   queries with synthetic IPs (`10.250.0.0/16`); the supervisor reverse-looks
   the synthetic address, matches the suffix, resolves the real hostname
   dial-time, and re-verifies the resolved IP (SSRF guard: private/loopback/
   link-local/CGNAT/ULA refused). Direct connects to synthetic addresses are
   refused, so the range cannot be borrowed to bypass literal rules.
2. **HTTP(S) header injection + host masking (Block B)** — `http_auth`
   credential rules (`env:`/`file:`/`fd:` secret sources, bearer/basic/header/
   apikey/query shapes, `replace`/`add-only`) injected by the MITM proxy after
   the ACL check; `host_mask` rewrites the wire `Host` header
   (`${PORT}` substituted). HTTP ACL `*.suffix` host matching (subdomains only,
   not the bare apex).

Both are exercised hermeticly: unit tests for the verdicts/matcher/SOCKS5 wire
protocol, and integration tests that run real sandboxes against local
fixtures (loopback DNS gateway, transparent proxy, no external network).

## Optional unprivileged enhancements on the same branch (2026-09-01+)

The branch also carries opt-in unprivileged isolation features, all usable
as uid 65534 (defaults stay off, so the PR's network scope is unaffected):

- **`pid_ns`** — per-sandbox `CLONE_NEWPID` (two-stage fork, pid 1 in the
  sandbox), procfs renumbered by ns, on-behalf `/proc` reads restricted to a
  read-only metadata whitelist.
- **independent host uid** — `RunAs` any host uid via parent-written userns
  maps (true DAC file/socket isolation); unprivileged supervisors that
  cannot map an arbitrary uid fail closed instead of silently using the
  caller's uid.
- **`net_isolation`** — per-sandbox `unshare(CLONE_NEWNET)` + loopback
  (no `CAP_NET_ADMIN` needed), with supervisor fd injection
  (`SECCOMP_IOCTL_NOTIF_ADDFD`) for outbound TCP/connected-UDP, an in-netns
  DNS gateway (so the `ip_unprivileged_port_start` sysctl is no longer
  needed), datagram on-behalf send, and inbound port mapping (host 50005+).

These are deliberately opt-in and independent of the PR's default paths.
When pushing, they can be included in the same PR or split into a follow-up
per upstream preference.

## Commits (all on `upstream-pr/netns-free-clean`)

- `d3a28cc` Block A (domain wildcards + loopback DNS gateway) + Block B
  (header inject / host mask / HTTP `*.suffix`) — the fork's tree with the
  per-sandbox netns/veth machinery removed.
- `55709f2` Block C — SOCKS5 egress on-behalf (unprivileged).
- `b6ef050` non-root test setup: shared pre-seeded fixtures +
  `stderr_tee` fallback, so the whole suite passes as an unprivileged uid.
- `53a8ee2` 0.9.0-beta metadata + multi-credential inject.
- `a6d2060` per-sandbox seccomp notify rate limit.
- `f471ffb` + `62efe62` per-sandbox PID namespace (`pid_ns`).
- `edac017` + `f5a1696` independent host uid (userns single-entry).
- `924627a` + `12c41cd` connect fd injection (`fd_inject_connect`).
- `5e44729` + `c8f8580` per-sandbox netns isolation (`net_isolation`).
- `3e6d73b` in-netns DNS gateway for wildcard rules.
- `9a5d476` + `b8e2e95` connected-UDP injection + datagram on-behalf.
- `3a07995` inbound port mapping.
- `d6940de` FFI/Python exposure of the new opt-in switches.

The optional per-sandbox netns branch stays on the fork and is deliberately
excluded.

## Verification

All green **as an unprivileged user** (uid 65534; the container entrypoint
does the one-time root prep — sysctl for the `:53` gateway + pre-seeded
`198.18.0.x`/`/etc/hosts` fixtures — then drops privileges):

```text
sandlock-core lib:       770 passed, 0 failed
integration (serial):    432 passed, 0 failed
python:                  430 passed, 0 skipped
```

## Notes for review

- The DNS gateway binds a per-sandbox `127.0.1.x` loopback port — no root
  network privileges; each sandbox gets its own address because resolv.conf
  cannot carry a port. The one deployment knob: glibc's resolv.conf cannot
  express a port, so the gateway uses the standard DNS port 53, which is
  below 1024. The platform must either allow unprivileged low-port binding
  once (`sysctl net.ipv4.ip_unprivileged_port_start=0`, or
  `CAP_NET_BIND_SERVICE` on the sandlock binary) or run the supervisor with
  that capability — after that one-time setting the whole product runs as a
  normal unprivileged user (verified: Landlock/seccomp sandbox, HTTP ACL
  proxy, virtual chroot, and the wildcard DNS+connect path all work as
  uid 65534).
- The netlink view adds one fixed documentation-only interface (`192.0.2.1`,
  RFC 5737) so `getaddrinfo`/`AI_ADDRCONFIG` performs DNS; the address is
  unreachable and leaks nothing.
- Fail closed everywhere: synthetic-IP direct connects, DNS rebinding to
  private ranges, unresolvable wildcard targets, and HTTP-rule matchers with
  malformed wildcards are refused at parse/build/connect time.
- The fork keeps a separate `feature/network-netns` branch (per-sandbox
  veth + loopback isolation, requires `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`) and a
  SOCKS5 egress-proxy branch; both are intentionally not part of this PR.

## Push / create

```bash
cd third_party/sandlock
git push origin upstream-pr/netns-free-clean
# then open a PR: multikernel/sandlock main ← imhun/sandlock upstream-pr/netns-free-clean
```

> 已推送（旧）：`origin/upstream-pr/netns-free-clean`（tip `53a8ee2`）。fork 以
> 子模块形式固定在本仓库 `third_party/sandlock`；改动先提交到子模块并 push，
> 再开 PR。**推送暂缓（用户指示 2026-09-01）**：本地 tip 现为 `d6940de`
> （含 S1/S2 增强），验证基线 lib `788 passed` / integration `465 passed` /
> Python `440 passed`（uid 65534）；推送与开 PR 待用户解除约束后执行。
