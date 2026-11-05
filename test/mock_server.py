#!/usr/bin/env python3
"""A tiny mock Mapepire server for testing mapepire.sh (test-only; stdlib only).

  mock_server.py --tls PORT CERT KEY   wss:// server mode (user "tester", password "secret")
  mock_server.py --single              single mode: newline-delimited JSON on stdin/stdout

Special SQL understood by the mock:
  rows(N)        result set of N rows (paged by "rows")
  big            one row with a 200 KB value (64-bit WebSocket length)
  frag           response sent as fragmented frames
  unicode        values that exercise JSON escaping
  FAIL           an SQL error
  insert/update  update_count 3
"""
import base64, hashlib, json, socket, ssl, struct, sys, threading

USER, PASSWORD = "tester", "secret"
JOB = "123456/QUSER/QZDASOINIT"


def dumps(obj):
    # Gson escapes HTML characters and non-ASCII by default; mimic that.
    s = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    for ch, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("=", "\\u003d"), ("'", "\\u0027")):
        s = s.replace(ch, esc)
    return s


def columns(*cols):
    return {"column_count": len(cols), "job": JOB,
            "columns": [{"name": n, "type": t, "display_size": 10, "label": n, "precision": 10, "scale": 0} for n, t in cols]}


class Session:
    def __init__(self):
        self.cursors = {}

    def handle(self, req):
        rid, typ = req.get("id"), req.get("type")
        base = {"id": rid}
        ok = lambda **kw: {**base, **kw, "success": True, "execution_time": 1}
        terse = req.get("terse", False)

        def result(cols, rows, n):
            block, rest = rows[:n], rows[n:]
            self.cursors[rid] = (cols, rest, terse)
            data = block if terse else [dict(zip([c[0] for c in cols], r)) for r in block]
            return ok(has_results=True, update_count=-1, metadata=columns(*cols), data=data, is_done=not rest)

        if typ == "connect":
            return ok(job=JOB)
        if typ in ("sql", "prepare_sql_execute"):
            sql = req.get("sql", "")
            n = req.get("rows", 1000)
            if "FAIL" in sql:
                return {**base, "success": False, "error": "[SQL0204] FAIL in *LIBL type *FILE not found.",
                        "sql_rc": -204, "sql_state": "42704", "execution_time": 1}
            if sql.lower().startswith(("insert", "update", "delete")):
                return ok(has_results=False, update_count=3)
            if sql.startswith("rows("):
                count = int(sql[5:sql.index(")")])
                rows = [[i + 1, "name %d" % (i + 1)] for i in range(count)]
                return result([("ID", "INTEGER"), ("NAME", "VARCHAR")], rows, n)
            if sql == "big":
                return result([("BIG", "CLOB")], [["x" * 200000]], n)
            if sql == "unicode":
                rows = [["café <b>&amp;</b> 'q' a=b", "\U0001F600", "tab\there\nnewline", None, 'quote " \\ /']]
                return result([("A", "VARCHAR"), ("B", "VARCHAR"), ("C", "VARCHAR"), ("D", "VARCHAR"), ("E", "VARCHAR")], rows, n)
            if typ == "prepare_sql_execute":
                return result([("PARAMS", "VARCHAR")], [[json.dumps(req.get("parameters"))]], n)
            return result([("SQL", "VARCHAR")], [[sql]], n)
        if typ == "sqlmore":
            cur = self.cursors.get(req.get("cont_id"))
            if cur is None:
                return {**base, "success": False, "error": "invalid correlation ID", "execution_time": 0}
            cols, rows, terse = cur
            n = req.get("rows", 1000)
            block, rest = rows[:n], rows[n:]
            self.cursors[req["cont_id"]] = (cols, rest, terse)
            data = block if terse else [dict(zip([c[0] for c in cols], r)) for r in block]
            return ok(data=data, is_done=not rest)
        if typ == "sqlclose":
            if self.cursors.pop(req.get("cont_id"), None) is None:
                return {**base, "success": False, "error": "invalid correlation ID", "execution_time": 0}
            return ok()
        if typ == "cl":
            cols = [("MESSAGE_ID", "VARCHAR"), ("SEVERITY", "INTEGER"), ("MESSAGE_TEXT", "VARCHAR")]
            if "BAD" in req.get("cmd", ""):
                rows = [["CPF2110", 40, "Library BAD not found."]]
                data = rows if terse else [dict(zip([c[0] for c in cols], r)) for r in rows]
                return {**base, "success": False, "error": "CPF2110", "has_results": True, "metadata": columns(*cols),
                        "data": data, "is_done": True, "execution_time": 1}
            rows = [["CPC2101", 0, "Library list changed."]]
            data = rows if terse else [dict(zip([c[0] for c in cols], r)) for r in rows]
            return ok(has_results=True, update_count=-1, metadata=columns(*cols), data=data, is_done=True)
        if typ == "ping":
            return ok(alive=True, db_alive=True)
        if typ == "getversion":
            return ok(build_date="2026-01-01", version="9.9.9-mock")
        if typ == "getdbjob":
            return ok(job=JOB)
        if typ == "exit":
            return ok()
        return {**base, "success": False, "error": "Unknown request type: %s" % typ, "execution_time": 0}


# ---------------------------------------------------------------- single mode
def single():
    s = Session()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        sys.stdout.write(dumps(s.handle(req)) + "\n")
        sys.stdout.flush()
        if req.get("type") == "exit":
            return


# ---------------------------------------------------------------- WebSocket
def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def send_frame(conn, op, payload, fin=True):
    hdr = bytes([(0x80 if fin else 0) | op])
    n = len(payload)
    if n < 126:
        hdr += bytes([n])
    elif n < 65536:
        hdr += bytes([126]) + struct.pack(">H", n)
    else:
        hdr += bytes([127]) + struct.pack(">Q", n)
    conn.sendall(hdr + payload)


def recv_message(conn):
    """Returns (opcode, payload) of the next complete message; checks client masking."""
    data, first_op = b"", None
    while True:
        b0, b1 = recv_exact(conn, 2)
        op, n = b0 & 15, b1 & 127
        if not b1 & 0x80:
            raise ValueError("client frame not masked")
        if n == 126:
            n = struct.unpack(">H", recv_exact(conn, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", recv_exact(conn, 8))[0]
        mask = recv_exact(conn, 4)
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(recv_exact(conn, n)))
        if op >= 8:
            return op, payload
        first_op = op if first_op is None else first_op
        data += payload
        if b0 & 0x80:
            return first_op, data


def serve_ws(conn):
    req = b""
    while b"\r\n\r\n" not in req:
        chunk = conn.recv(4096)
        if not chunk:
            return
        req += chunk
    lines = req.decode().split("\r\n")
    hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    if not lines[0].startswith("GET /db/"):
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        return
    if hdrs.get("authorization") != "Basic " + base64.b64encode(("%s:%s" % (USER, PASSWORD)).encode()).decode():
        conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
        return
    accept = base64.b64encode(hashlib.sha1((hdrs["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
    s = Session()
    while True:
        op, payload = recv_message(conn)
        if op == 8:
            send_frame(conn, 8, payload[:2])
            return
        if op == 10:
            sys.stderr.write("mock: got pong %r\n" % payload)
            continue
        req = json.loads(payload.decode())
        resp = dumps(s.handle(req)).encode()
        if req.get("type") == "ping":
            send_frame(conn, 9, b"\x00hello\xff")   # server ping (binary payload, with a NUL)
        if req.get("sql") == "frag":
            third = len(resp) // 3
            send_frame(conn, 1, resp[:third], fin=False)
            send_frame(conn, 0, resp[third:2 * third], fin=False)
            send_frame(conn, 0, resp[2 * third:])
        else:
            send_frame(conn, 1, resp)
        if req.get("type") == "exit":
            send_frame(conn, 8, struct.pack(">H", 1000) + b"bye")
            try:
                recv_message(conn)
            except Exception:
                pass
            return


def tls_server(port, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print("listening", flush=True)

    def run(raw):
        try:
            with ctx.wrap_socket(raw, server_side=True) as conn:
                serve_ws(conn)
        except Exception as e:  # noqa: BLE001 - log and drop the connection
            sys.stderr.write("mock: connection ended: %r\n" % e)

    while True:
        raw, _ = srv.accept()
        threading.Thread(target=run, args=(raw,), daemon=True).start()


if __name__ == "__main__":
    if sys.argv[1] == "--single":
        single()
    else:
        tls_server(int(sys.argv[2]), sys.argv[3], sys.argv[4])
