"""
Tests of the session counters of the VPP plugin (vppstats.c) without VPP.

vppstats.c is built as it is against a fake of the VPP stats client, see
vppstats/. The tests need a C compiler and nothing else: no VPP, no root, no
network. The C program has the tests, this file builds it and runs each of
them.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
TESTDIR = Path(__file__).resolve().parent / "vppstats"
HOOKDIR = ROOT / "accel-pppd" / "session_hooks" / "vyos_vpp"

TESTS = [
    "delta_accumulation",
    "bind_at_first_read",
    "counter_clear",
    "epoch_race_retry",
    "unknown_index_eagain",
    "stall_budget",
    "lookup_budget",
    "stall_backoff",
    "final_read_ignores_backoff",
    "final_reads_share_backoff",
    "frozen_total",
    "instance_replaced_bound",
    "instance_replaced_pending",
    "instance_replaced_during_creation",
    "no_socket_at_creation",
    "connect_failure_pending",
    "connect_race",
    "chmod_not_a_restart",
    "close_resets",
    "stall_after_epoch_change",
    "no_stall_while_beating",
    "probe_answers",
    "probe_stuck_vpp",
    "probe_no_vpp",
]


@pytest.fixture(scope="module")
def vppstats_test(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler")

    work = tmp_path_factory.mktemp("vppstats")
    exe = work / "vppstats_test"
    cmd = [
        cc,
        "-O0",
        "-g",
        "-Wall",
        "-Wextra",
        "-Wno-unused-parameter",
        "-Wno-old-style-declaration",
        "-DHAVE_SESSION_HOOKS",
        "-DAP_SESSIONID_LEN=16",
        "-DVPPSTATS_STALL_SEC=2",
        f'-DVPPSTATS_SOCKET="{work / "stats.sock"}"',
        f"-I{TESTDIR / 'fake'}",
        f"-I{TESTDIR}",
        f"-I{ROOT / 'accel-pppd' / 'include'}",
        f"-I{HOOKDIR}",
        str(HOOKDIR / "vppstats.c"),
        str(TESTDIR / "fake_stat_client.c"),
        str(TESTDIR / "vppstats_test.c"),
        "-lpthread",
        "-o",
        str(exe),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    return exe


def test_vppstats_test_list(vppstats_test):
    """The list of tests in the C program and in this file is the same"""
    res = subprocess.run(
        [vppstats_test, "--list"], capture_output=True, text=True, timeout=10
    )
    assert res.stdout.split() == TESTS


@pytest.mark.parametrize("name", TESTS)
def test_vppstats(vppstats_test, name):
    res = subprocess.run(
        [vppstats_test, name], capture_output=True, text=True, timeout=60
    )
    assert res.returncode == 0, res.stdout + res.stderr
