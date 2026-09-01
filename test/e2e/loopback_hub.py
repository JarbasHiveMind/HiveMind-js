#!/usr/bin/env python3
"""Self-contained end-to-end test for the HiveMind JavaScript client.

Boots a real hivemind-core hub on a loopback transport (via ``hivescope``),
registers a satellite, then launches the Node.js driver (``js_e2e_driver.mjs``)
which loads the actual ``static/js/hivemind.js`` client, connects over a real
WebSocket, performs the full Protocol V1 password handshake, and sends an
encrypted ``recognizer_loop:utterance``. The Python side then asserts the hub
received that exact utterance.

This mirrors the interop test in the HiveMind test harness but lives in this
repo so the JS client can be verified end-to-end on its own. It is hermetic:
no external network, no published registry, no fixed ports.

Requirements (test-only, see ``requirements.txt``):
  - hivemind-core, hivescope, hivemind-bus-client  (the loopback hub)
  - Node.js >= 18 on PATH, with the ``ws`` package resolvable

Run directly::

    python3 test/e2e/loopback_hub.py

or via pytest::

    pytest test/e2e/loopback_hub.py
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DRIVER = HERE / "js_e2e_driver.mjs"

NAME = "js-sat"
PASSWORD = "correct-horse-battery-hivemind-js-e2e"
UTTERANCE = "hello from javascript"


def _node_available() -> bool:
    return shutil.which("node") is not None


def _run_driver(url: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Point the driver at this repo's client explicitly.
    env.setdefault("HIVEMIND_JS_PATH", str(REPO_ROOT / "static" / "js" / "hivemind.js"))
    # Make a node_modules with `ws` resolvable if one sits next to the driver.
    node_modules = HERE / "node_modules"
    if node_modules.is_dir():
        existing = env.get("NODE_PATH", "")
        env["NODE_PATH"] = (
            f"{node_modules}{os.pathsep}{existing}" if existing else str(node_modules)
        )
    return subprocess.run(
        ["node", str(DRIVER), url, NAME, NAME, PASSWORD, UTTERANCE],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def run_e2e() -> None:
    """Boot the loopback hub, drive the JS client, assert the round-trip."""
    from hivescope.topology import TopologyBuilder

    builder = TopologyBuilder()
    master = builder.add_master("M0", use_loopback=True)
    master.register_satellite(
        NAME, password=PASSWORD, allowed_types=["recognizer_loop:utterance"]
    )
    builder.start_all()

    try:
        url = master.network_protocol.url
        print(f"[*] loopback hub listening at {url}")

        result = _run_driver(url)
        print("---- node stdout ----")
        print(result.stdout)
        print("---- node stderr ----")
        print(result.stderr)

        assert result.returncode == 0, (
            f"JS driver exited {result.returncode}"
        )

        injected = master.agent_protocol.injected
        utterances = [m for m in injected if m.msg_type == "recognizer_loop:utterance"]
        assert utterances, (
            "hub received no recognizer_loop:utterance from the JS client; "
            f"injected={injected}"
        )

        # The utterance text round-tripped through the real handshake + AES-GCM.
        spoken = []
        for m in utterances:
            spoken += (m.data or {}).get("utterances", [])
        assert UTTERANCE in spoken, f"utterance text not found on hub: {spoken}"

        # Session context is propagated (not the 'default' fallback).
        for m in utterances:
            session_id = ((m.context or {}).get("session", {})).get("session_id", "")
            assert session_id and session_id != "default", (
                f"missing/default session_id in context: {m.context}"
            )

        print("[+] E2E PASSED: JS client round-tripped an utterance through a real hub")
    finally:
        builder.stop_all()


# ── pytest entry point ────────────────────────────────────────────────────────

def test_js_client_roundtrip_through_real_hub():
    import pytest

    if not _node_available():
        pytest.skip("Node.js not available on PATH")
    if not DRIVER.exists():
        pytest.skip(f"driver missing: {DRIVER}")
    try:
        import hivescope  # noqa: F401
        import hivemind_core  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        pytest.skip(f"hub deps not installed: {exc}")
    run_e2e()


if __name__ == "__main__":
    if not _node_available():
        sys.exit("Node.js not found on PATH; install Node >= 18 to run the E2E test")
    if not DRIVER.exists():
        sys.exit(f"driver missing: {DRIVER}")
    run_e2e()
