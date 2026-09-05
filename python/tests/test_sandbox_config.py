# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.sandbox."""

from __future__ import annotations

import pytest

from sandlock.sandbox import (
    Sandbox,
    parse_memory_size,
    parse_ports,
)


class TestParseMemorySize:
    def test_plain_bytes(self):
        assert parse_memory_size("1024") == 1024

    def test_kilobytes(self):
        assert parse_memory_size("100K") == 100 * 1024

    def test_megabytes(self):
        assert parse_memory_size("512M") == 512 * 1024 ** 2

    def test_gigabytes(self):
        assert parse_memory_size("1G") == 1024 ** 3

    def test_terabytes(self):
        assert parse_memory_size("2T") == 2 * 1024 ** 4

    def test_case_insensitive(self):
        assert parse_memory_size("512m") == 512 * 1024 ** 2

    def test_fractional(self):
        assert parse_memory_size("1.5G") == int(1.5 * 1024 ** 3)

    def test_whitespace(self):
        assert parse_memory_size("  512M  ") == 512 * 1024 ** 2

    def test_invalid(self):
        with pytest.raises(ValueError):
            parse_memory_size("not_a_size")

    def test_empty(self):
        with pytest.raises(ValueError):
            parse_memory_size("")


class TestEnsureNative:
    """``_ensure_native`` rebuilds on every call so that mutations to
    config fields between lifecycle invocations are not silently
    masked by a stale native cache."""

    def test_rebuilds_on_each_call(self):
        sb = Sandbox(fs_readable=["/usr"])
        first = sb._ensure_native()
        second = sb._ensure_native()
        # Two distinct native objects (rebuild, not cache hit).
        assert first is not second

    def test_picks_up_post_construction_mutation(self):
        sb = Sandbox(fs_readable=["/usr"])
        sb._ensure_native()                 # first build
        sb.fs_readable = ["/usr", "/etc"]   # user mutates after first run
        rebuilt = sb._ensure_native()       # second build sees mutation
        # The rebuilt native is a fresh object; the cached self._native
        # was replaced, not retained from the pre-mutation state.
        assert rebuilt is sb._native


class TestIsolationFields:
    """S1.1/S2 FFI exposure: ``pid_ns`` / ``net_isolation`` /
    ``fd_inject_connect`` / ``port_mappings`` round-trip through the native
    builder with fail-closed validation."""

    def test_defaults_off(self):
        p = Sandbox()
        assert p.pid_ns is False
        assert p.net_isolation is False
        assert p.fd_inject_connect is False
        assert p.port_mappings is None

    def test_empty_port_mappings_treated_as_off(self):
        assert Sandbox(port_mappings={}).port_mappings == {}
        assert Sandbox(port_mappings=None).port_mappings is None

    def test_fields_roundtrip_to_native_build(self):
        p = Sandbox(
            pid_ns=True,
            net_isolation=True,
            fd_inject_connect=True,
            port_mappings={50005: 8080},
        )
        native = p._ensure_native()
        assert native.ptr

    def test_port_mappings_without_net_isolation_fails_closed(self):
        p = Sandbox(port_mappings={50005: 8080})
        with pytest.raises(RuntimeError, match="net_isolation"):
            p._ensure_native()

    def test_host_port_below_50005_rejected(self):
        with pytest.raises(ValueError, match="50005"):
            Sandbox(port_mappings={50004: 8080})

    def test_host_port_out_of_u16_range_rejected(self):
        with pytest.raises(ValueError, match="50005"):
            Sandbox(port_mappings={70000: 8080})

    def test_sandbox_port_zero_rejected(self):
        with pytest.raises(ValueError, match="range"):
            Sandbox(port_mappings={50005: 0})

    def test_duplicate_sandbox_port_rejected(self):
        with pytest.raises(ValueError, match="duplicate sandbox port"):
            Sandbox(port_mappings={50005: 8080, 50006: 8080})

    def test_non_int_mapping_rejected(self):
        with pytest.raises(ValueError, match="must be ints"):
            Sandbox(port_mappings={50005: "8080"})

    def test_non_mapping_rejected(self):
        with pytest.raises(ValueError, match="must be a dict"):
            Sandbox(port_mappings=[(50005, 8080)])


class TestPolicy:
    def test_defaults(self):
        p = Sandbox()
        assert p.fs_writable == []
        assert p.fs_readable == []
        assert p.fs_denied == []
        assert p.extra_deny_syscalls == []
        assert p.extra_allow_syscalls == []
        assert p.net_allow_bind == []
        assert p.net_allow == []
        assert p.max_memory is None
        # F5.1 (Q10): max_processes is a whole-box ceiling; the default rose
        # from the legacy per-command 64 to 256.
        assert p.max_processes == 256
        assert p.max_cpu is None


class TestMediationRunAs:
    """F6.1 (SL-1): the mediation identity tier round-trips to the native
    builder (caller default / explicit supervisor) with fail-closed
    validation at the Python boundary."""

    def test_defaults_to_caller(self):
        assert Sandbox().mediation_run_as == "caller"

    def test_supervisor_roundtrips_to_native_build(self):
        p = Sandbox(mediation_run_as="supervisor")
        assert p._ensure_native().ptr

    def test_invalid_tier_rejected(self):
        with pytest.raises(ValueError, match="mediation_run_as"):
            Sandbox(mediation_run_as="root")

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_memory="512M")
        p.max_memory = "1G"
        assert p.max_memory == "1G"

    def test_memory_bytes_string(self):
        p = Sandbox(max_memory="512M")
        assert p.memory_bytes() == 512 * 1024 ** 2

    def test_memory_bytes_int(self):
        p = Sandbox(max_memory=1024)
        assert p.memory_bytes() == 1024

    def test_memory_bytes_none(self):
        p = Sandbox()
        assert p.memory_bytes() is None

    def test_cpu_pct(self):
        p = Sandbox(max_cpu=50)
        assert p.cpu_pct() == 50

    def test_cpu_pct_none(self):
        p = Sandbox()
        assert p.cpu_pct() is None

    def test_cpu_pct_clamped(self):
        assert Sandbox(max_cpu=0).cpu_pct() == 1
        assert Sandbox(max_cpu=200).cpu_pct() == 100


class TestDiskQuotaPolicy:
    def test_default_none(self):
        p = Sandbox()
        assert p.max_disk is None

    def test_string_value(self):
        p = Sandbox(max_disk="1G")
        assert p.max_disk == "1G"

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_disk="512M")
        p.max_disk = "1G"
        assert p.max_disk == "1G"

    def test_parse_memory_size_for_disk(self):
        assert parse_memory_size("1G") == 1024 ** 3
        assert parse_memory_size("512M") == 512 * 1024 ** 2
        assert parse_memory_size("100K") == 100 * 1024


class TestParsePorts:
    def test_single_int(self):
        assert parse_ports([80]) == [80]

    def test_single_string(self):
        assert parse_ports(["443"]) == [443]

    def test_range(self):
        assert parse_ports(["8000-8003"]) == [8000, 8001, 8002, 8003]

    def test_mixed(self):
        assert parse_ports([80, "443", "8000-8002"]) == [80, 443, 8000, 8001, 8002]

    def test_comma_in_string(self):
        # A string element may hold a comma list / ranges, matching the CLI's
        # --net-allow-bind grammar.
        assert parse_ports(["8080,9090"]) == [8080, 9090]
        assert parse_ports(["8080,9000-9002", 443]) == [443, 8080, 9000, 9001, 9002]

    def test_comma_empty_part_rejected(self):
        with pytest.raises(ValueError):
            parse_ports(["8080,"])

    def test_dedup(self):
        assert parse_ports([80, "80", "79-81"]) == [79, 80, 81]

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            parse_ports(["9000-8000"])

    def test_out_of_range(self):
        with pytest.raises(ValueError):
            parse_ports([70000])

    def test_bad_format(self):
        with pytest.raises(ValueError):
            parse_ports(["abc"])

    def test_empty(self):
        assert parse_ports([]) == []


class TestNetPolicy:
    def test_unrestricted_by_default(self):
        p = Sandbox()
        assert p.net_allow_bind == []
        assert p.net_allow == []


class TestEnvControl:
    def test_clean_env_default_off(self):
        p = Sandbox()
        assert p.clean_env is False

    def test_env_default_empty(self):
        p = Sandbox()
        assert p.env == {}

    def test_clean_env_on(self):
        p = Sandbox(clean_env=True)
        assert p.clean_env is True

    def test_env_set(self):
        p = Sandbox(env={"FOO": "bar", "BAZ": "qux"})
        assert p.env == {"FOO": "bar", "BAZ": "qux"}


class TestGpuDevices:
    def test_default_none(self):
        p = Sandbox()
        assert p.gpu_devices is None

    def test_specific_devices(self):
        p = Sandbox(gpu_devices=[0, 2])
        assert p.gpu_devices == [0, 2]

    def test_all_gpus(self):
        p = Sandbox(gpu_devices=[])
        assert p.gpu_devices == []


class TestCpuCores:
    def test_default_none(self):
        p = Sandbox()
        assert p.cpu_cores is None

    def test_specific_cores(self):
        p = Sandbox(cpu_cores=[0, 2, 3])
        assert p.cpu_cores == [0, 2, 3]


class TestNetAllow:
    """Endpoint allowlist semantics for `net_allow`.

    Each entry is a string spec parsed by the native build:
    `host:port[,port,...]`, `:port`, or `*:port`. Empty list = deny all.
    """

    def test_default_is_empty(self):
        p = Sandbox()
        assert p.net_allow == []

    def test_specs_preserved_as_strings(self):
        p = Sandbox(net_allow=["api.example.com:443", "github.com:22,443", ":8080"])
        assert list(p.net_allow) == [
            "api.example.com:443",
            "github.com:22,443",
            ":8080",
        ]


class TestNetDeny:
    """Endpoint denylist semantics for `net_deny` (default-allow, inverse of
    `net_allow`, mutually exclusive with it). Targets are literal IP/CIDR."""

    def test_default_is_empty(self):
        assert Sandbox().net_deny == []

    def test_specs_preserved_as_strings(self):
        p = Sandbox(net_deny=["10.0.0.0/8", "169.254.169.254:80", "udp://*"])
        assert list(p.net_deny) == ["10.0.0.0/8", "169.254.169.254:80", "udp://*"]
