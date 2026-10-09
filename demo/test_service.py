"""Safety/regression tests for the local recording API."""
import json
import sys
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
BASE="http://127.0.0.1:8091"
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from agent.advisory_triage import parse_recommendation

def request(path,data=None):
    payload=None if data is None else json.dumps(data).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(BASE+path,data=payload),timeout=10) as response:
            return response.status,json.load(response)
    except urllib.error.HTTPError as error:
        return error.code,json.load(error)

class SafetyTests(unittest.TestCase):
    def test_model_cannot_select_commands_or_extra_fields(self):
        self.assertEqual(parse_recommendation('{"action":"patch","summary":"Reject unsafe identifiers"}')["action"],"patch")
        for value in ('{"action":"exec","summary":"unsafe"}',
            '{"action":"patch","summary":"valid","command":"curl bad"}',
            '{"action":"patch","summary":""}', "x"*4097):
            with self.assertRaises(ValueError): parse_recommendation(value)

    def test_unknown_action_and_payload_rejected(self):
        self.assertEqual(request("/api/exec",{})[0],404)
        self.assertEqual(request("/api/run",{"command":"touch /tmp/unsafe"})[0],400)
    def test_serialized_flow_and_kernel_evidence(self):
        self.assertEqual(request("/api/reset",{})[0],200)
        code,state=request("/api/run",{})
        self.assertEqual(code,202)
        self.assertEqual(request("/api/run",{})[0],409)
        self.assertEqual(request("/api/reset",{})[0],409)
        for _ in range(1100):
            _,state=request("/api/state")
            if state["status"]!="running": break
            time.sleep(.1)
        self.assertEqual(state["status"],"complete",state["error"])
        self.assertEqual(state["tests"]["passed"],4)
        self.assertTrue(state["reviewReady"])
        self.assertTrue(Path(state["reviewPath"]).is_file())
        self.assertEqual({x["kind"] for x in state["incidents"]},{"open","connect"})
        for incident in state["incidents"]:
            self.assertEqual(incident["runId"],state["runId"])
            self.assertEqual(incident["verdict"],"deny")
            self.assertTrue(any(e.get("pid")==incident["pid"] and e["verdict"]=="deny" for e in state["events"]))
        _,idle=request("/api/reset",{})
        self.assertEqual(idle["status"],"idle")
        self.assertEqual(idle["incidents"],[])
        self.assertFalse(idle["reviewReady"])
        self.assertIsNone(idle["runId"])
if __name__=="__main__": unittest.main(verbosity=2)
