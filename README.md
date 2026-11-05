# mapepire-bash

A pure bash client for [Mapepire](https://mapepire-ibmi.github.io/), the database
server for IBM i Db2. It's a single file, `mapepire.sh`. You can run it as a command
(one-off queries, scripts, or an interactive SQL shell) or source it as a library.

It follows the [Mapepire protocol](https://github.com/Mapepire-IBMi/mapepire-protocol)
and implements every part of it with bash builtins: the HTTP upgrade, WebSocket framing
and masking, Base64, the SHA-1 handshake check, and JSON encoding, parsing and
rendering. No `jq`, `curl`, `sed`, `awk` or `base64` is needed.

## Transports

| Mode | How it connects | Needs |
|---|---|---|
| **Server mode** | `wss://host:8076/db/` to a running Mapepire server. **TLS is always used.** | bash 4.2+, `openssl` |
| **Single mode** | Starts a server with `--single` and talks JSON over its stdin/stdout, either locally on IBM i or through a command such as `ssh`. | bash 4.2+ |

Bash can't do TLS by itself, so in server mode `openssl s_client` serves only as the
encrypted pipe. Everything above the TLS layer is bash. There is deliberately no
option for unencrypted `ws://`.

## Quick start

```sh
# One query
./mapepire.sh -H myibmi -u MYUSER "select * from qiws.qcustcdt"

# Interactive SQL shell (prompts for the password)
./mapepire.sh -H myibmi -u MYUSER

# Single mode, directly on IBM i (no network, no TLS, no password)
./mapepire.sh --single "/QOpenSys/pkgs/bin/mapepire --single" "values current user"

# Single mode through ssh
./mapepire.sh --single "ssh myibmi /QOpenSys/pkgs/bin/mapepire --single"
```

Example output:

```
 CUSNUM | LSTNAM   | CITY   | BALDUE
--------+----------+--------+--------
 938472 | Henning  | Dallas |  37.00
 839283 | Jones    | Clay   | 100.00
(2 rows)
```

## Certificates

The server certificate is verified against the system trust store, and its host
name or IP address is checked. Mapepire servers often use a self-signed
certificate. To trust one:

```sh
./mapepire.sh -H myibmi --print-cert > myibmi.pem   # check its fingerprint, then:
./mapepire.sh -H myibmi -u MYUSER --ca myibmi.pem "values 1"
```

`-k` / `--insecure` skips verification. The connection is still encrypted, but you
can't be sure who is on the other end.

## Command line

```
Usage: mapepire.sh [OPTIONS] [SQL...]
```

| Option | Meaning |
|---|---|
| `-H, --host`, `-p, --port`, `-u, --user`, `-P, --password` | Server, port (default 8076), and credentials. Also read from `MAPEPIRE_HOST`, `MAPEPIRE_PORT`, `MAPEPIRE_USER` and `MAPEPIRE_PASSWORD`. If no password is given, it is prompted for. |
| `--ca FILE`, `-k`, `--print-cert` | TLS trust settings (see above) |
| `-S, --single COMMAND` | Use single mode instead of server mode |
| `--props`, `--technique`, `--application` | JDBC properties (`"naming=system;libraries=MYLIB"`), `tcp`/`cli`, and job tracking name |
| `-c, --cl COMMAND` | Run a CL command and show the job log it produced |
| `-f, --file FILE` | Run the statements in a file (`-` for stdin) |
| `--param VALUE` (repeatable), `--params JSON` | Values for `?` parameter markers |
| `-F, --format` | `table` (default), `csv`, `vertical`, or `json` (raw responses, one per line, for `jq`) |
| `-r, --rows N`, `-m, --max-rows N` | Rows per round trip; stop after N rows |
| `--ping`, `--server-version`, `--debug` | Health check, server version, protocol trace to stderr |

Positional SQL, `-c` and `-f` run in the order given. In files, on stdin, and in the
interactive shell, a statement ends with `;` at the end of a line. Lines starting
with `--` are comments. The interactive shell has readline editing and history,
plus these commands: `\cl CMD`, `\format FMT`, `\rows N`, `\ping`, `\version`,
`\job`, `\help` and `\quit`.

```sh
./mapepire.sh -H myibmi -u MYUSER -F csv "select * from qiws.qcustcdt" > customers.csv
./mapepire.sh -H myibmi -u MYUSER --param 938472 "select * from qiws.qcustcdt where cusnum = ?"
./mapepire.sh -H myibmi -u MYUSER -c "CHGLIBL LIBL(QGPL QTEMP)"
./mapepire.sh -H myibmi -u MYUSER -f nightly.sql
```

The exit status is 0 on success, 1 if any statement failed, and 2 for usage errors.

## Library

```bash
source ./mapepire.sh

MP_HOST=myibmi MP_USER=MYUSER MP_PASSWORD=secret MP_CA=myibmi.pem
mp_connect || { echo "$MP_ERROR" >&2; exit 1; }

mp_sql "select cusnum, lstnam from qiws.qcustcdt" 2 && cursor=$MP_ID
mp_get data.0.LSTNAM && echo "first customer: $REPLY"
mp_get is_done
while [[ $REPLY == false ]]; do
    mp_sqlmore "$cursor" 2 || break
    mp_print_result csv
    mp_get is_done
done
mp_sqlclose "$cursor"

mp_close
```

- **Settings** (set before `mp_connect`): `MP_HOST`, `MP_PORT`, `MP_USER`,
  `MP_PASSWORD`, `MP_CA`, `MP_TLS_VERIFY` (0 = insecure), `MP_SINGLE`, `MP_PROPS`,
  `MP_TECHNIQUE`, `MP_APPLICATION`, `MP_TERSE` (1 = rows as arrays), `MP_ROWS`,
  `MP_DEBUG`.
- **Requests**: `mp_sql`, `mp_prepare_sql`, `mp_prepare_sql_execute SQL PARAMS_JSON`,
  `mp_execute CONT_ID PARAMS_JSON`, `mp_sqlmore`, `mp_sqlclose`, `mp_cl`, `mp_dove`,
  `mp_ping`, `mp_getdbjob`, `mp_getversion`, `mp_setconfig key=value...`,
  `mp_gettracedata`, and `mp_request TYPE 'json members'` for anything else. Each
  returns 0 when the server reports success. Otherwise it returns 1 and sets
  `MP_ERROR`, including SQLSTATE/SQLCODE when available.
- **Responses**: `MP_RESPONSE` holds the raw JSON. `MP_JSON` is the response
  flattened into paths like `data.0.NAME`, `metadata.columns.1.type`, and `data.#`
  (array length). `mp_get PATH` puts the decoded value in `REPLY` and returns 1 for
  null or missing values. `mp_count PATH` gives an array length. `mp_print_result FMT`
  renders the rows. `MP_ID` is the id of the last request, which is also the cursor
  handle.
- **Helpers**: `mp_json_str` and `mp_json_array` build JSON for parameters, e.g.
  `mp_json_array A01 B02; mp_prepare_sql_execute "... in (?, ?)" "$REPLY"`.

Notes for library use: sourcing turns on `extglob`. The functions return values in
`REPLY` rather than printing them, so no subshells are needed. A shell holds one
connection at a time.

## Requirements and limits

- **bash 4.2 or newer.** macOS ships bash 3.2, so use a newer bash there
  (e.g. from Homebrew). On IBM i, use bash from the open source package repos.
- **Native Windows `openssl.exe`** (e.g. `/mingw64/bin/openssl` in Git for Windows)
  checks stdin only once per second, which adds about a second to each round trip.
  An MSYS/Cygwin build (`/usr/bin/openssl`) doesn't have this problem, and neither
  do Linux, macOS, AIX or IBM i.
- Bash handles large results correctly but not quickly. A 1000-row block takes
  about half a second to parse. Use `-m` to limit rows, and use `-F json` with `jq`
  for heavy processing.
- Very large *requests* (e.g. multi-megabyte batch parameters) are slow to send,
  because every byte is masked in bash.

## Tests

```sh
bash test/unit.sh          # Base64, SHA-1, JSON, rendering (no server needed)
bash test/integration.sh   # end to end against test/mock_server.py over real TLS, plus single mode
bash test/perf.sh          # timings for large JSON values
```

The integration tests need `python3` and `openssl`. They use a mock server, not a
real IBM i.

## License

Apache-2.0
