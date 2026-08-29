# SPDX-License-Identifier: Apache-2.0
"""Tests for the Python ``http_inject`` / ``host_mask`` bindings (Block B).

``_serialize_http_inject`` is pure Python and runs on any host; the FFI
builders are exercised where the native library is available.
"""

from __future__ import annotations

import pytest

from sandlock._sdk import _serialize_http_inject
from sandlock.sandbox import Sandbox


class TestSerializeHttpInject:
    def test_bare_host_defaults_method_and_path(self):
        assert _serialize_http_inject(
            {"matcher": "api.example.com", "auth": "bearer", "secret": "env:KEY"}, 0
        ) == ("inject0", "env:KEY", "* api.example.com/* bearer inject0")

    def test_host_with_path_defaults_method(self):
        assert _serialize_http_inject(
            {"matcher": "api.example.com/v1/*", "auth": "bearer", "secret": "env:KEY"}, 0
        ) == ("inject0", "env:KEY", "* api.example.com/v1/* bearer inject0")

    def test_full_matcher_and_add_only(self):
        assert _serialize_http_inject(
            {
                "matcher": "GET api.example.com/v1/*",
                "auth": "header:x-api-key",
                "secret": "file:/run/secrets/key",
                "name": "upstream",
                "on_existing": "add-only",
            },
            3,
        ) == (
            "upstream",
            "file:/run/secrets/key",
            "GET api.example.com/v1/* header:x-api-key upstream add-only",
        )

    def test_wildcard_suffix_matcher_passes_through(self):
        name, secret, rule = _serialize_http_inject(
            {"matcher": "*.example.com", "auth": "bearer", "secret": "env:KEY"}, 1
        )
        assert rule == "* *.example.com/* bearer inject1"

    def test_basic_auth_with_user(self):
        _, _, rule = _serialize_http_inject(
            {"matcher": "svc.example.com", "auth": "basic:robot", "secret": "env:KEY"}, 0
        )
        assert rule == "* svc.example.com/* basic:robot inject0"

    def test_fd_source_allowed(self):
        assert _serialize_http_inject(
            {"matcher": "svc.example.com", "auth": "query:key", "secret": "fd:0"}, 0
        ) == ("inject0", "fd:0", "* svc.example.com/* query:key inject0")

    @pytest.mark.parametrize(
        "rule",
        [
            {"matcher": "x.com", "auth": "bearer", "secret": "literal:sekrit"},
            {"matcher": "x.com", "auth": "bearer", "secret": "env:"},
            {"matcher": "x.com", "auth": "bearer", "secret": "plain"},
            {"matcher": "x.com", "auth": "otp", "secret": "env:KEY"},
            {"matcher": "x.com", "auth": "header:", "secret": "env:KEY"},
            {"matcher": "x.com", "auth": "bearer", "secret": "env:KEY", "on_existing": "merge"},
            {"matcher": "GET a b/c", "auth": "bearer", "secret": "env:KEY"},
            {"matcher": "", "auth": "bearer", "secret": "env:KEY"},
            {"matcher": "x.com", "auth": "bearer", "secret": "env:KEY", "bogus": 1},
            {"matcher": "x.com", "auth": "bearer", "secret": "env:KEY", "name": ""},
        ],
    )
    def test_rejects_malformed(self, rule):
        with pytest.raises(ValueError):
            _serialize_http_inject(rule, 0)


class TestSandboxFields:
    def test_defaults(self):
        p = Sandbox()
        assert p.http_inject == []
        assert p.host_mask is None

    def test_accepts_inject_and_host_mask(self):
        p = Sandbox(
            http_allow=["GET api.example.com/*"],
            http_inject=[
                {
                    "matcher": "api.example.com",
                    "auth": "bearer",
                    "secret": "env:KEY",
                }
            ],
            host_mask="localhost:${PORT}",
        )
        assert p.host_mask == "localhost:${PORT}"
        assert p.http_inject[0]["auth"] == "bearer"
