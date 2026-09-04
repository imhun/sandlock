# sandlock fork test baseline — Linux 7.0.14-orbstack-00380-ga7e0a2dc9535, Landlock ABI 8, Python 3.11.16

# Measured 2026-09-04 in sandlock-dev:latest (Debian trixie x86_64, cargo 1.98,
# python 3.11.16), repo mounted at /src, --privileged; kernel
# 7.0.14-orbstack-00380-ga7e0a2dc9535; Landlock ABI 8 (read via
# sandlock.landlock_abi_version() from the FFI debug lib).
#
# Two-phase full gate (see scripts/test-all.sh header):
#   1. non-root phase (entrypoint drops to uid 65534): core_lib, core_integ,
#      ffi, cli, cli_build, python — `sh scripts/test-all.sh`
#   2. root-mode phase: oci — `sh scripts/test-all.sh --oci-root` as root.
core_lib = 791 # F1.4 (SL-8): +1 plan unit test pidfd_release_is_idempotent
               # in resource.rs
core_integ = 477 # F1.4 (SL-8): +2 plan tests in test_resource.rs
                 # (test_setsid_orphan_returns_proc_count,
                 # test_proc_count_matches_live_after_orphan_storm); the F1.3
                 # control-auth pair (471 -> 475) is included in this total
ffi = 89
cli = 95      # after F0.4 wiring (cli suite includes net_bind_map tests)
oci = 131     # ROOT-MODE: run via scripts/test-all.sh --oci-root as root. oci e2e
              # supervises OCI-default root containers; S1.2 fail-closes
              # RunAs(0,0) for non-root supervisors (tested feature). 131 = 53+65+13
              # (lib + bin + integration: the bin target recompiles the crate
              # module tests, so the F1.2 pair supervisor::tests::
              # early_exits_cap_drops_overflow / test_unknown_pid_exit_frame_bounded
              # runs in both unit targets, +4 over 127 = 51+63+13).
cli_build = 0 # workspace release build gate (no test binaries; 0 = build passed)
python = 441  # fork S2.x-era python tests landed after the plan's 430/431 estimate
