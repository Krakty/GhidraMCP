#!/usr/bin/env python3
"""
Concurrency test for bridge_mcp_ghidra_multi.py per-port serialization.

Verifies:
  1. Per-port lock serializes same-port calls (no interleaving)
  2. Different-port calls run independently (cross-port parallelism)
  3. port_busy_timeout when lock acquisition times out
  4. busy-vs-absent detection (TCP open vs closed classification)

Uses mock HTTP servers (http.server) simulating GhidraMCP backends.
No live Ghidra required.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

# Ensure the bridge module is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bridge_mcp_ghidra_multi as bridge


# ---------------------------------------------------------------------------
# Mock GhidraMCP backend — simulates a slow /info + /decompile endpoint
# ---------------------------------------------------------------------------

class MockGhidraHandler(BaseHTTPRequestHandler):
    """Simulates a GhidraMCP HTTP backend with configurable latency."""

    # Class-level state for test control
    request_log: list[tuple[str, float]] = []  # (port_label, timestamp)
    log_lock = threading.Lock()
    latency: float = 0.1  # seconds of simulated work per request
    fail_info: bool = False  # if True, /info returns 500

    def log_message(self, format, *args):
        pass  # silence stderr noise during tests

    def do_GET(self):
        if self.path.startswith("/info") or self.path == "/":
            if self.__class__.fail_info:
                self.send_error(500, "Simulated failure")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            name = self.server.config.get("name", "mock.exe")
            date = self.server.config.get("datePrefix", "03-16-2026")
            self.wfile.write(json.dumps({
                "version": "0.3.0",
                "port": self.server.config.get("port", 8090),
                "toolName": "CodeBrowser",
                "name": name,
                "datePrefix": date,
            }).encode())
        elif self.path.startswith("/decompile_function"):
            # Simulate slow decompile
            time.sleep(self.__class__.latency)
            with self.__class__.log_lock:
                self.__class__.request_log.append(
                    (self.server.config.get("label", "?"), time.time()))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"int foo() { return 42; }")
        else:
            self.send_error(404, "Not found")

    def do_POST(self):
        # Simulate slow POST
        time.sleep(self.__class__.latency)
        with self.__class__.log_lock:
            self.__class__.request_log.append(
                (self.server.config.get("label", "?"), time.time()))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "data": "done"}).encode())


def _make_server(port: int, name: str, date: str = "03-16-2026") -> HTTPServer:
    """Create a mock GhidraMCP HTTP server on localhost:<port>."""
    server = HTTPServer(("127.0.0.1", port), MockGhidraHandler)
    server.config = {
        "port": port,
        "name": name,
        "datePrefix": date,
        "label": f"{date} {name} @ {port}",
    }
    return server


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestPerPortSerialization(unittest.TestCase):
    """Verify same-port serialization and cross-port independence."""

    @classmethod
    def setUpClass(cls):
        """Start two mock GhidraMCP backends on localhost."""
        MockGhidraHandler.request_log.clear()
        MockGhidraHandler.latency = 0.05  # fast but measurable

        cls.server_a = _make_server(18990, "mock_a.exe")
        cls.server_b = _make_server(18991, "mock_b.exe")

        cls.thread_a = threading.Thread(target=cls.server_a.serve_forever, daemon=True)
        cls.thread_b = threading.Thread(target=cls.server_b.serve_forever, daemon=True)
        cls.thread_a.start()
        cls.thread_b.start()
        time.sleep(0.1)  # let servers start

    @classmethod
    def tearDownClass(cls):
        cls.server_a.shutdown()
        cls.server_b.shutdown()

    def setUp(self):
        MockGhidraHandler.request_log.clear()
        MockGhidraHandler.fail_info = False
        # Reset bridge state
        bridge._scanner = None
        bridge._client_cache.clear()
        bridge._port_locks.clear()

    # ------------------------------------------------------------------
    # Test 1: Same-port calls serialize
    # ------------------------------------------------------------------

    def test_same_port_calls_are_serialized(self):
        """Fire 3 concurrent requests at the SAME port — all must complete in order."""
        scanner = bridge.PortScanner("127.0.0.1", 18990, 18991)
        scanner.scan()

        # Temporarily override global scanner
        bridge._scanner = scanner

        MockGhidraHandler.latency = 0.1  # 100ms per request
        results = []
        errors = []
        lock = threading.Lock()

        def call_query(idx: int):
            try:
                r = bridge.ghidra_query(port=18990, action="decompile",
                                        args={"address": "0x1000"})
                with lock:
                    results.append((idx, r))
            except Exception as e:
                with lock:
                    errors.append((idx, str(e)))

        threads = [threading.Thread(target=call_query, args=(i,)) for i in range(3)]
        start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.time() - start
        bridge._scanner = None

        # All 3 should succeed
        self.assertEqual(len(results), 3, f"Errors: {errors}")
        for _, r in results:
            self.assertTrue(r.get("ok"), f"Request failed: {r}")

        # Serial execution: total time >= 3 * 100ms = 300ms
        # Parallel execution would be ~100ms
        self.assertGreaterEqual(elapsed, 0.25,
            f"Same-port calls appear to run in parallel ({elapsed:.3f}s < 0.25s)")

    # ------------------------------------------------------------------
    # Test 2: Different-port calls run independently
    # ------------------------------------------------------------------

    def test_different_ports_run_concurrently(self):
        """Fire requests at DIFFERENT ports — they should overlap."""
        scanner = bridge.PortScanner("127.0.0.1", 18990, 18991)
        scanner.scan()
        bridge._scanner = scanner

        MockGhidraHandler.latency = 0.15  # 150ms per request
        results = []
        errors = []
        lock = threading.Lock()

        def call_port_a():
            try:
                r = bridge.ghidra_query(port=18990, action="decompile",
                                        args={"address": "0x1000"})
                with lock:
                    results.append(("a", r))
            except Exception as e:
                with lock:
                    errors.append(("a", str(e)))

        def call_port_b():
            try:
                r = bridge.ghidra_query(port=18991, action="decompile",
                                        args={"address": "0x2000"})
                with lock:
                    results.append(("b", r))
            except Exception as e:
                with lock:
                    errors.append(("b", str(e)))

        start = time.time()
        ta = threading.Thread(target=call_port_a)
        tb = threading.Thread(target=call_port_b)
        ta.start()
        tb.start()
        ta.join()
        tb.join()
        elapsed = time.time() - start
        bridge._scanner = None

        self.assertEqual(len(results), 2, f"Errors: {errors}")
        for _, r in results:
            self.assertTrue(r.get("ok"), f"Request failed: {r}")

        # Cross-port: total time should be ~150ms (not 300ms)
        self.assertLess(elapsed, 0.30,
            f"Different-port calls appear serialized ({elapsed:.3f}s >= 0.30s)")

    # ------------------------------------------------------------------
    # Test 3: Lock timeout produces port_busy_timeout
    # ------------------------------------------------------------------

    def test_port_busy_timeout(self):
        """Hold the per-port lock and verify second caller gets timeout."""
        scanner = bridge.PortScanner("127.0.0.1", 18990, 18991)
        scanner.scan()
        bridge._scanner = scanner

        # Acquire the lock for port 18990 externally
        with bridge._port_locks_lock:
            if 18990 not in bridge._port_locks:
                bridge._port_locks[18990] = threading.Lock()
            external_lock = bridge._port_locks[18990]

        acquired = external_lock.acquire()  # hold indefinitely
        self.assertTrue(acquired)

        # Temporarily reduce timeout for fast test
        original_timeout = bridge.PORT_LOCK_TIMEOUT
        bridge.PORT_LOCK_TIMEOUT = 0.1

        try:
            result = bridge.ghidra_query(port=18990, action="info")
            self.assertFalse(result.get("ok"))
            self.assertEqual(result.get("status"), "port_busy_timeout")
            self.assertIn("could not acquire lock", result.get("error", ""))
        finally:
            bridge.PORT_LOCK_TIMEOUT = original_timeout
            external_lock.release()
            bridge._scanner = None

    # ------------------------------------------------------------------
    # Test 4: Single request still works (no regression)
    # ------------------------------------------------------------------

    def test_single_request_works(self):
        """Single request should complete normally with no lock contention."""
        scanner = bridge.PortScanner("127.0.0.1", 18990, 18991)
        scanner.scan()
        bridge._scanner = scanner

        result = bridge.ghidra_query(port=18990, action="info")
        bridge._scanner = None

        self.assertTrue(result.get("ok"), f"Single request failed: {result}")
        self.assertIn("data", result)

    # ------------------------------------------------------------------
    # Test 5: Lock is released after exception
    # ------------------------------------------------------------------

    def test_lock_released_after_error(self):
        """If a request raises, the lock must still be released."""
        scanner = bridge.PortScanner("127.0.0.1", 18990, 18991)
        scanner.scan()
        bridge._scanner = scanner

        # Cause an error by passing invalid args
        result = bridge.ghidra_query(port=18990, action="decompile",
                                     args={"bad": "args"})
        bridge._scanner = None

        # Should fail (no 'name' or 'address' in args) but NOT hang
        self.assertFalse(result.get("ok"))

        # Lock should be free now — verify by sending a valid request
        scanner2 = bridge.PortScanner("127.0.0.1", 18990, 18991)
        scanner2.scan()
        bridge._scanner = scanner2
        result2 = bridge.ghidra_query(port=18990, action="info")
        bridge._scanner = None
        self.assertTrue(result2.get("ok"), f"Lock not released after error")


class TestBusyVsAbsent(unittest.TestCase):
    """Verify TCP-level busy-vs-absent classification."""

    @classmethod
    def setUpClass(cls):
        cls.server = _make_server(18992, "mock_present.exe")
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        MockGhidraHandler.fail_info = False

    def test_healthy_port_is_neither_busy_nor_absent(self):
        """A healthy port is listed in backends, not in busy/absent."""
        scanner = bridge.PortScanner("127.0.0.1", 18992, 18992)
        backends = scanner.scan()

        self.assertIn(18992, backends)
        with scanner._lock:
            self.assertNotIn(18992, scanner._absent_ports)
            self.assertNotIn(18992, scanner._busy_ports)

    def test_tcp_open_but_http_fail_is_busy(self):
        """TCP open + HTTP /info fails → classified BUSY (not absent)."""
        MockGhidraHandler.fail_info = True

        scanner = bridge.PortScanner("127.0.0.1", 18992, 18992)
        backends = scanner.scan()

        self.assertNotIn(18992, backends)
        with scanner._lock:
            self.assertIn(18992, scanner._busy_ports)
            self.assertNotIn(18992, scanner._absent_ports)

    def test_tcp_closed_is_absent(self):
        """No server on port → TCP closed → classified ABSENT."""
        scanner = bridge.PortScanner("127.0.0.1", 18993, 18993)
        backends = scanner.scan()

        self.assertNotIn(18993, backends)
        with scanner._lock:
            self.assertNotIn(18993, scanner._busy_ports)
            self.assertIn(18993, scanner._absent_ports)

    def test_busy_status_expires(self):
        """Busy status should expire after PORT_BUSY_STATUS_TTL."""
        MockGhidraHandler.fail_info = True

        scanner = bridge.PortScanner("127.0.0.1", 18992, 18992)
        scanner.scan()

        # Artificially age the busy timestamp
        with scanner._lock:
            old_ts = scanner._busy_ports.get(18992)
            self.assertIsNotNone(old_ts)
            scanner._busy_ports[18992] = time.time() - bridge.PORT_BUSY_STATUS_TTL - 1.0

        # Now run ghidra_discover logic — the busy entry should be filtered out
        now = time.time()
        with scanner._lock:
            busy = {
                p: ts for p, ts in scanner._busy_ports.items()
                if now - ts < bridge.PORT_BUSY_STATUS_TTL
            }
        self.assertNotIn(18992, busy)

    def test_successful_probe_clears_stale_state(self):
        """A successful /info probe clears any prior busy/absent flags."""
        scanner = bridge.PortScanner("127.0.0.1", 18992, 18992)

        # Pre-set stale state
        with scanner._lock:
            scanner._absent_ports.add(18992)
            scanner._busy_ports[18992] = time.time()

        MockGhidraHandler.fail_info = False
        backends = scanner.scan()

        self.assertIn(18992, backends)
        with scanner._lock:
            self.assertNotIn(18992, scanner._absent_ports)
            self.assertNotIn(18992, scanner._busy_ports)


# ---------------------------------------------------------------------------
# Integration test description (for manual run against live bridge)
# ---------------------------------------------------------------------------

INTEGRATION_TEST_PLAN = """
## Integration Concurrency Test (Manual)

### Prerequisites
- Ghidra running with 2+ CodeBrowser windows on different ports
- bridge_mcp_ghidra_multi.py running with --ghidra-host <host>

### Test A: Same-port serialization
```bash
# Fire 3 simultaneous decompiles at the SAME port — use background jobs
for i in 1 2 3; do
  (time curl -s -X POST "http://HOST:PORT/decompile" --data-urlencode "name=FUN_BIG") &
done
wait
# Expect: all 3 complete, total wall-clock ≈ 3× single-request time
```

### Test B: Cross-port independence
```bash
# Fire decompile at port A and port B simultaneously
(time curl -s -X POST "http://HOST:8090/decompile" --data-urlencode "name=FUN_BIG") &
(time curl -s -X POST "http://HOST:8091/decompile" --data-urlencode "name=FUN_BIG") &
wait
# Expect: both complete in parallel, wall-clock ≈ 1× single-request time
```

### Test C: port_busy_timeout via MCP
```python
# Via the MCP bridge tools — fire 2 rapid ghidra_query calls at the same port
# The second should either queue (lock acquired after first releases) or
# return port_busy_timeout if PORT_LOCK_TIMEOUT is exceeded
ghidra_query(port=8090, action="decompile", args={"name":"FUN_BIG_COMPLEX"})
# Immediately fire another:
ghidra_query(port=8090, action="info")
# Expect: second call queues behind first, completes after first releases
```

### Test D: busy-vs-absent detection
```bash
# 1. Normal state: ghidra_discover() returns backends
ghidra_discover()
# Expect: backends listed, no busy_ports/absent_ports keys (or empty)

# 2. Simulate busy: start a long-running script on port 8090
ghidra_query(port=8090, action="run_script", args={"script_body":"import time; time.sleep(30)"})
# While that runs, immediately call ghidra_discover()
ghidra_discover()
# Expect: port 8090 shows in busy_ports with status "busy"

# 3. Stop Ghidra on port 8092, then:
ghidra_discover()
# Expect: port 8092 shows in absent_ports
```
"""


if __name__ == "__main__":
    # Run unit tests
    unittest.main(verbosity=2)
