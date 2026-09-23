import ast
import concurrent.futures
import http.client
import http.server
import json
import pathlib
import socket
import sys
import threading
import time
import unittest
import urllib.parse


SOURCE = pathlib.Path(__file__).with_name("cold-object-finalization-20260923-replay.py")
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    SOURCE = pathlib.Path(sys.argv.pop(1))


class RequestPhaseTests(unittest.TestCase):
    def check_phase(self, cached):
        parked = threading.Event()
        release = threading.Event()
        recorded = threading.Event()

        class Gate:
            def __enter__(self):
                parked.set()
                if not release.wait(5):
                    raise TimeoutError("request was not released")

            def __exit__(self, *_):
                pass

        class Events(list):
            def append(self, event):
                super().append(event)
                recorded.set()

        def forbid_capture(*_):
            raise AssertionError("a frozen request must never fetch upstream")

        key = ("/delayed", "json")
        namespace = dict(
            http=http,
            socket=socket,
            threading=threading,
            time=time,
            json=json,
            urllib=urllib,
            state_lock=threading.Lock(),
            locks={key: Gate()},
            entries={key: ({"status": 200, "content_type": "text/plain"}, b"fixed", False)}
            if cached else {},
            events=Events(),
            misses=[],
            frozen=True,
            phase="original",
            profile="zero",
            capture=forbid_capture,
        )
        module = ast.parse(SOURCE.read_text())
        names = {"identity", "Server", "Handler"}
        module.body = [node for node in module.body if getattr(node, "name", None) in names]
        self.assertEqual({node.name for node in module.body}, names)
        exec(compile(module, str(SOURCE), "exec"), namespace)
        server = namespace["Server"](("127.0.0.1", 0), namespace["Handler"])
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        def request(method, target, body=None):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                connection.request(method, target, body)
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            response = pool.submit(request, "GET", key[0])
            self.assertTrue(parked.wait(5), "GET did not reach the response gate")
            self.assertEqual(request("POST", "/_control", json.dumps({"phase": "next"}))[0], 200)
            release.set()
            self.assertEqual(response.result(timeout=5)[0], 200 if cached else 502)
            self.assertTrue(recorded.wait(5), "GET did not record its event")
            self.assertEqual(namespace["phase"], "next")
            self.assertEqual(namespace["misses"], [] if cached else [("original", key)])
            self.assertEqual(namespace["events"][0]["phase"], "original")
        finally:
            release.set()
            pool.shutdown(wait=True)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

    def test_response_keeps_phase_from_request_arrival(self):
        self.check_phase(cached=True)

    def test_frozen_miss_keeps_phase_from_request_arrival(self):
        self.check_phase(cached=False)


if __name__ == "__main__":
    unittest.main()
