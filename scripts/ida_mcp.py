#!/usr/bin/env python3
"""Minimal MCP (streamable HTTP) client for the IDA MCP server.

Usage:
    python scripts/ida_mcp.py list
    python scripts/ida_mcp.py call <tool_name> '<json arguments>'
    python scripts/ida_mcp.py --url http://127.0.0.1:13337/mcp list
"""
import argparse
import json
import sys
import urllib.request

DEFAULT_URL = "http://127.0.0.1:13337/mcp"


class MCP:
    def __init__(self, url):
        self.url = url
        self.sid = None
        self.next_id = 1

    def _post(self, payload, notify=False):
        data = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
        req = urllib.request.Request(self.url, data=data, headers=headers,
                                     method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self.sid = sid
            body = resp.read().decode("utf-8", "replace")
        if notify or not body.strip():
            return None
        text = body.strip()
        if text.startswith("{"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
        payloads = [ln[5:].strip() for ln in text.splitlines()
                    if ln.startswith("data:")]
        objs = []
        for p in payloads:
            try:
                objs.append(json.loads(p))
            except json.JSONDecodeError:
                pass
        if not objs and payloads:
            try:
                objs = [json.loads("\n".join(payloads))]
            except json.JSONDecodeError:
                pass
        if not objs:
            raise RuntimeError("cannot parse MCP response: %r" % body[:400])
        for o in objs:
            if isinstance(o, dict) and ("result" in o or "error" in o):
                return o
        return objs[-1]

    def initialize(self):
        r = self._post({
            "jsonrpc": "2.0", "id": self.next_id, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "dsh", "version": "1"}}})
        self.next_id += 1
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"},
                   notify=True)
        return r

    def request(self, method, params=None):
        r = self._post({"jsonrpc": "2.0", "id": self.next_id, "method": method,
                        "params": params or {}})
        self.next_id += 1
        return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--brief", action="store_true")
    ap.add_argument("cmd", choices=("list", "call", "init"))
    ap.add_argument("tool", nargs="?")
    ap.add_argument("args", nargs="*", default=[],
                    help="key=value pairs (ints/JSON auto-detected) or a single "
                         "{...} JSON blob")
    a = ap.parse_args()

    parsed = {}
    if len(a.args) == 1 and a.args[0].lstrip().startswith("{"):
        parsed = json.loads(a.args[0])
    else:
        for item in a.args:
            if "=" not in item:
                sys.exit("bad argument %r (expected key=value)" % item)
            k, v = item.split("=", 1)
            try:
                parsed[k] = json.loads(v)
            except json.JSONDecodeError:
                parsed[k] = v

    m = MCP(a.url)
    info = m.initialize()
    if a.cmd == "init":
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return
    if a.cmd == "list":
        r = m.request("tools/list")
        tools = (r or {}).get("result", {}).get("tools", [])
        for t in tools:
            print("- %s: %s" % (t.get("name"), (t.get("description") or "")[:110]))
            props = (t.get("inputSchema") or {}).get("properties") or {}
            if props:
                print("    args: %s" % ", ".join(sorted(props)))
        if not tools:
            print(json.dumps(r, ensure_ascii=False)[:2000])
        return
    r = m.request("tools/call", {"name": a.tool, "arguments": parsed})
    if a.brief:
        brief(r)
    else:
        print(json.dumps(r, ensure_ascii=False, indent=2))


def brief(r):
    """Compact printer for disasm / xrefs results."""
    res = (r or {}).get("result", {})
    text = ""
    for item in res.get("content", []):
        if item.get("type") == "text":
            text = item["text"]
            break
    if text:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and "asm" in obj:
            print("FUNC %s 0x%s" % (obj["asm"].get("name"),
                                    obj["asm"].get("start_ea")))
            for ln in obj["asm"].get("lines", []):
                print("  %-7s %s" % (ln.get("addr"), ln.get("instruction")))
            return
        if isinstance(obj, list) and obj and isinstance(obj[0], dict) \
                and "xrefs" in obj[0]:
            for t in obj:
                print("XREFS to %s (%d):" % (t.get("addr"), t.get("xref_count", 0)))
                for x in t.get("xrefs", []):
                    fn = (x.get("fn") or {})
                    print("   from %-9s %s" % (x.get("addr"),
                                               fn.get("name") or "?"))
            return
        if isinstance(obj, list):
            print(json.dumps(obj, ensure_ascii=False)[:6000])
            return
    print(json.dumps(res, ensure_ascii=False)[:6000])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:                                   # noqa: BLE001
        sys.exit("MCP error: %s" % exc)
