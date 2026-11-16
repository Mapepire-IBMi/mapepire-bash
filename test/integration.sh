#!/usr/bin/env bash
# End-to-end tests for mapepire.sh against the Mapepire mock server
# (https://github.com/Mapepire-IBMi/mapepire-mockserver), over real TLS WebSockets
# and over single mode. Needs java 8+ and openssl; curl if the jar must be downloaded.
#
#   MOCK_JAR=/path/to/mapepire-mockserver.jar   use this jar instead of downloading it
#   MOCK_PORT=18076                             port for the mock server
cd "$(dirname "$0")/.." || exit 1
MOCK_VERSION=0.2.0
MOCK_SHA256=fbba22bc3cfa26e2351cb72dccc7a9ede52104d3b8e9faceb728e21544d58e2f
MOCK_URL=https://github.com/Mapepire-IBMi/mapepire-mockserver/releases/download/v$MOCK_VERSION/mapepire-mockserver-v$MOCK_VERSION.jar
PORT=${MOCK_PORT:-18076}
TMP=${TMPDIR:-/tmp}/mapepire-test.$$
mkdir -p "$TMP"

command -v java >/dev/null || { echo "java is required to run the mock server"; exit 1; }
# Native Windows openssl.exe polls stdin once per second; prefer the MSYS/Cygwin build.
[[ $OSTYPE == msys* || $OSTYPE == cygwin* ]] && [[ -x /usr/bin/openssl ]] && PATH=/usr/bin:$PATH

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else openssl dgst -sha256 -r "$1"; fi; }
JAR=${MOCK_JAR:-test/.cache/mapepire-mockserver-v$MOCK_VERSION.jar}
if [[ -z $MOCK_JAR && ! -f $JAR ]]; then
    echo "downloading $MOCK_URL"
    mkdir -p "${JAR%/*}"
    curl -fsSL -o "$JAR.part" "$MOCK_URL" || { echo "cannot download the mock server"; exit 1; }
    sum=$(sha256 "$JAR.part")
    [[ ${sum%% *} == "$MOCK_SHA256" ]] || { rm -f "$JAR.part"; echo "mock server jar has the wrong SHA-256: ${sum%% *}"; exit 1; }
    mv "$JAR.part" "$JAR"
fi
[[ -f $JAR ]] || { echo "mock server jar not found: $JAR"; exit 1; }

java -jar "$JAR" --host 127.0.0.1 --port "$PORT" >"$TMP/mock.log" 2>&1 &
MOCK=$!
trap 'kill $MOCK 2>/dev/null; wait $MOCK 2>/dev/null; rm -rf "$TMP"' EXIT
for ((i = 0; i < 60; i++)); do
    grep -q listening "$TMP/mock.log" 2>/dev/null && break
    kill -0 $MOCK 2>/dev/null || break
    sleep 0.5
done
grep -q listening "$TMP/mock.log" || { echo "mock server did not start:"; cat "$TMP/mock.log"; exit 1; }

pass=0 fail=0
check() { # name expected actual
    if [[ $3 == "$2" ]]; then pass=$((pass + 1)); echo "ok   $1"
    else fail=$((fail + 1)); printf 'FAIL %s\n--- expected\n%s\n--- actual\n%s\n' "$1" "$2" "$3"; fi
}
check_has() { # name needle haystack
    if [[ $3 == *"$2"* ]]; then pass=$((pass + 1)); echo "ok   $1"
    else fail=$((fail + 1)); printf 'FAIL %s\n--- expected to contain\n%s\n--- actual\n%s\n' "$1" "$2" "$3"; fi
}

# ---------------------------------------------------------------- TLS and authentication
# The mock server uses a bundled self-signed certificate for localhost / 127.0.0.1
./mapepire.sh -H 127.0.0.1 -p "$PORT" --print-cert >"$TMP/cert.pem"; rc=$?
check "print cert" "0|-----BEGIN CERTIFICATE-----" "$rc|$(head -1 "$TMP/cert.pem")"
check_has "print cert is the mock's certificate" "Mapepire Mock Server" "$(openssl x509 -in "$TMP/cert.pem" -noout -subject 2>&1)"
out=$(./mapepire.sh -H 127.0.0.1 -p 1 --print-cert 2>&1); rc=$?
check "print cert, nothing listening" "1|mapepire: could not retrieve a certificate from 127.0.0.1:1" "$rc|$out"

MP=(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u mock -P mockingbird --ca "$TMP/cert.pem")
DEPT_COLS=' DEPTNO | DEPTNAME                     | MGRNO  | ADMRDEPT | LOCATION '
DEPT_DASH='--------+------------------------------+--------+----------+----------'

check "connect + query" $'IBMREQD\nY' "$("${MP[@]}" -F csv "select * from sysibm.sysdummy1")"
check "user profile is not case-sensitive" $'IBMREQD\nY' "$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u MoCk -P mockingbird --ca "$TMP/cert.pem" -F csv "select * from sysibm.sysdummy1")"
check "second user" $'IBMREQD\nY' "$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u MOCK2 -P mockeroni --ca "$TMP/cert.pem" -F csv "select * from sysibm.sysdummy1")"
out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u mock -P wrong --ca "$TMP/cert.pem" "values 1" 2>&1); rc=$?
# The mock answers bad credentials with 404 (a real server sends 401, which the
# client reports as "authentication failed"); either way the upgrade must fail.
check "bad password" "1|mapepire: WebSocket upgrade failed: HTTP/1.1 404" "$rc|${out% WebSocket Upgrade*}"
out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u mock -P MOCKINGBIRD --ca "$TMP/cert.pem" "values 1" 2>&1); rc=$?
check "password is case-sensitive" "1|mapepire: WebSocket upgrade failed: HTTP/1.1 404" "$rc|${out% WebSocket Upgrade*}"
out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u nobody -P mockingbird --ca "$TMP/cert.pem" "values 1" 2>&1); rc=$?
check "unknown user" "1|mapepire: WebSocket upgrade failed: HTTP/1.1 404" "$rc|${out% WebSocket Upgrade*}"
out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u mock -P mockingbird "values 1" 2>&1); rc=$?
check "untrusted cert rejected" 1 "$rc"
check_has "untrusted cert message" "TLS connection to 127.0.0.1:$PORT failed" "$out"
check_has "untrusted cert hint" "--print-cert > server.pem" "$out"
check "insecure (-k) accepted" $'IBMREQD\nY' "$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u mock -P mockingbird -k -F csv "select * from sysibm.sysdummy1")"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/other.key" -out "$TMP/other.pem" -days 1 \
    -subj "/CN=other" >/dev/null 2>&1 || MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMP/other.key" -out "$TMP/other.pem" -days 1 -subj "/CN=other" >/dev/null 2>&1
out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u mock -P mockingbird --ca "$TMP/other.pem" "values 1" 2>&1); rc=$?
check "wrong CA rejected" 1 "$rc"
out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u mock -P mockingbird --ca "$TMP/missing.pem" "values 1" 2>&1); rc=$?
check "missing CA file" "1|mapepire: cannot read CA file: $TMP/missing.pem" "$rc|$out"
out=$(./mapepire.sh -H 127.0.0.1 -p 1 -u mock -P mockingbird -k "values 1" 2>&1); rc=$?
check "connection refused" 1 "$rc"
check_has "connection refused message" "TLS connection to 127.0.0.1:1 failed" "$out"
out=$(MAPEPIRE_HOST=127.0.0.1 MAPEPIRE_PORT=$PORT MAPEPIRE_USER=mock MAPEPIRE_PASSWORD=mockingbird MAPEPIRE_CA=$TMP/cert.pem \
    ./mapepire.sh -F csv "select * from sysibm.sysdummy1")
check "settings from environment" $'IBMREQD\nY' "$out"
out=$(MAPEPIRE_PASSWORD=wrong "${MP[@]}" -F csv "select * from sysibm.sysdummy1")
check "-P overrides MAPEPIRE_PASSWORD" $'IBMREQD\nY' "$out"
check "--opt=value syntax" $'IBMREQD\nY' "$(./mapepire.sh --host=127.0.0.1 --port="$PORT" --user=mock --password=mockingbird --ca="$TMP/cert.pem" --format=csv "select * from sysibm.sysdummy1")"
out=$("${MP[@]}" --technique bogus "values 1" 2>&1); rc=$?
check "invalid technique" "1|mapepire: Invalid connection technique specified" "$rc|$out"
check "technique cli" $'IBMREQD\nY' "$("${MP[@]}" --technique cli -F csv "select * from sysibm.sysdummy1")"
check "props and application" $'IBMREQD\nY' "$("${MP[@]}" --props "naming=system;libraries=QGPL" --application tests -F csv "select * from sysibm.sysdummy1")"

# ---------------------------------------------------------------- Usage errors (no connection needed)
out=$(./mapepire.sh -F xml "values 1" 2>&1); check "bad format" "2|mapepire: format must be table, csv, vertical or json" "$?|$out"
out=$(./mapepire.sh "values 1" 2>&1); check "no host" "2|mapepire: no host given (use --host, or --single for single mode)" "$?|$out"
out=$(./mapepire.sh -H h "values 1" 2>&1); check "no user" "2|mapepire: no user given (use --user)" "$?|$out"
out=$(./mapepire.sh -H h -u u "values 1" </dev/null 2>&1); check "no password" "2|mapepire: no password given (use --password or MAPEPIRE_PASSWORD)" "$?|$out"
out=$(./mapepire.sh --bogus 2>&1); check "unknown option" "2|mapepire: unknown option: --bogus (see --help)" "$?|$out"
out=$(./mapepire.sh -H 2>&1); check "option needs a value" "2|mapepire: option -H needs a value" "$?|$out"
out=$(./mapepire.sh -H h -r ten 2>&1); check "rows must be a number" "2|mapepire: expected a number, got 'ten'" "$?|$out"
out=$(./mapepire.sh -H h -p x 2>&1); check "port must be a number" "2|mapepire: expected a number, got 'x'" "$?|$out"
check_has "version" "mapepire.sh " "$(./mapepire.sh --version)"
check_has "help" "Usage: mapepire.sh [OPTIONS] [SQL...]" "$(./mapepire.sh --help)"

# ---------------------------------------------------------------- Results and formats
check "table" $' IBMREQD \n---------\n Y       \n(1 row)' "$("${MP[@]}" "select * from sysibm.sysdummy1")"
out=$("${MP[@]}" "select * from sample.department")
check "table: 14 rows with NULLs" "$DEPT_COLS"$'\n'"$DEPT_DASH"$'\n A00    | SPIFFY COMPUTER SERVICE DIV. | 000010 | A00      | NULL     ' "$(head -3 <<<"$out")"
check "table: footer" $' J22    | BRANCH OFFICE J2             | NULL   | E01      | NULL     \n(14 rows)' "$(tail -2 <<<"$out")"
check "csv: NULL is empty" $'DEPTNO,DEPTNAME,MGRNO,ADMRDEPT,LOCATION\nA00,SPIFFY COMPUTER SERVICE DIV.,000010,A00,\nB01,PLANNING,000020,A00,\nC01,INFORMATION CENTER,000030,A00,\nD01,DEVELOPMENT CENTER,,A00,' \
    "$("${MP[@]}" -F csv -m 4 "select * from sample.department")"
check "vertical" $'-[ RECORD 1 ]--------------------\nDEPTNO   | A00\nDEPTNAME | SPIFFY COMPUTER SERVICE DIV.\nMGRNO    | 000010\nADMRDEPT | A00\nLOCATION | NULL\n-[ RECORD 2 ]--------------------\nDEPTNO   | B01\nDEPTNAME | PLANNING\nMGRNO    | 000020\nADMRDEPT | A00\nLOCATION | NULL' \
    "$("${MP[@]}" -F vertical -m 2 "select * from sample.department")"
check "vertical numbering continues across blocks" $'-[ RECORD 3 ]--------------------' "$("${MP[@]}" -F vertical -r 2 -m 3 "select * from sample.department" | grep RECORD | tail -1)"
out=$("${MP[@]}" -F json "select * from sysibm.sysdummy1")
check_has "json: raw response" '"data":[["Y"]]' "$out"
check_has "json: metadata" '"name":"IBMREQD","type":"CHAR"' "$out"
check "json: one line per response" 1 "$(wc -l <<<"$out")"
check "json: one line per block" 4 "$("${MP[@]}" -F json -r 4 "select * from sample.department" | wc -l)"
check "numbers right-aligned" $' N   | S   \n-----+-----\n   1 | a   \n 100 | bcd \n(2 rows)' \
    "$("${MP[@]}" "select 1 as N, 'a' as S union all select 100, 'bcd' order by 1")"
check "empty result: table" $' X \n---\n(0 rows)' "$("${MP[@]}" "select 1 as X where 1 = 0")"
check "empty result: csv" "X" "$("${MP[@]}" -F csv "select 1 as X where 1 = 0")"
check "unicode + escapes" $'A,B,C,D,E\ncafé <b>&amp;</b> \'q\' a=b,😀,"tab\there\nnewline",,"quote "" \\ /"' \
    "$("${MP[@]}" -F csv "select 'café <b>&amp;</b> ''q'' a=b' as A, char(128512) as B, 'tab'||char(9)||'here'||char(10)||'newline' as C, null as D, 'quote \" \\ /' as E")"
check "unicode in table width (UTF-8 locale)" $' A    | B \n------+---\n café | x \n(1 row)' "$(LC_ALL=C.UTF-8 "${MP[@]}" "select 'café' as A, 'x' as B")"
out=$("${MP[@]}" -F csv "select printf('%.*c', 200000, 'x') as BIG")
check "200 KB value (64-bit frame length)" 200004 "${#out}"
out=$("${MP[@]}" -F csv "select '$(printf '%*s' 70000 '' | tr ' ' y)' as S")
check "70 KB request (64-bit client frame length)" 70002 "${#out}"
check "column labels" $'first name,2nd\nx,2' "$("${MP[@]}" -F csv "select 'x' as \"first name\", 2 as \"2nd\"")"

# ---------------------------------------------------------------- Paging
out=$("${MP[@]}" -F csv -r 7 "select * from sample.department")
check "paging: all rows, one header" 15 "$(wc -l <<<"$out")"
check "paging: last row" "J22,BRANCH OFFICE J2,,E01," "$(tail -1 <<<"$out")"
check "max rows csv" $'DEPTNO\nA00\nB01\nC01' "$("${MP[@]}" -F csv -r 2 -m 3 "select * from sample.department" | cut -d, -f1)"
check_has "max rows table" "(5 rows)" "$("${MP[@]}" -m 5 "select * from sample.department")"
check "max rows bigger than result" 15 "$("${MP[@]}" -F csv -m 100 "select * from sample.department" | wc -l)"
check "max rows stops fetching" 2 "$("${MP[@]}" -F json -r 3 -m 5 "select * from sample.department" | wc -l)"

# The big one: a table of 5000 rows, read back 13 rows at a time (385 blocks)
CTE="with recursive c(x) as (select 1 union all select x + 1 from c where x < 5000)"
"${MP[@]}" -F csv -r 13 --debug \
    "create table qtemp.big (id integer not null primary key, name varchar(20))" \
    "insert into qtemp.big $CTE select x, 'name ' || x from c" \
    "select * from qtemp.big order by id" >"$TMP/big.csv" 2>"$TMP/big.log"; rc=$?
check "5000 rows: exit code" 0 "$rc"
check "5000 rows: insert count" 1 "$(grep -c '<< .*"update_count":5000,' "$TMP/big.log")"
mapfile -t lines <"$TMP/big.csv"
check "5000 rows: row count" 5001 "${#lines[@]}"
check "5000 rows: header and first row" "id,name|1,name 1" "${lines[0]}|${lines[1]}"
check "5000 rows: last row" "5000,name 5000" "${lines[5000]}"
bad=0; for ((i = 1; i <= 5000; i++)); do [[ ${lines[i]} == "$i,name $i" ]] || { bad=$i; break; }; done
check "5000 rows: every row in order" 0 "$bad"
check "5000 rows: 1 sql + 384 sqlmore requests" 384 "$(grep -c '>> .*"type":"sqlmore"' "$TMP/big.log")"
check "5000 rows: 13 rows per request" 384 "$(grep -c '>> .*"type":"sqlmore".*"rows":13' "$TMP/big.log")"

# Same thing through the library: insert the 5000 rows as one batch (a ~100 KB
# request), then page through them 13 at a time and check every block.
out=$(
    source ./mapepire.sh
    MP_HOST=127.0.0.1 MP_PORT=$PORT MP_USER=mock MP_PASSWORD=mockingbird MP_CA=$TMP/cert.pem MP_TERSE=1
    mp_connect || { echo "connect: $MP_ERROR"; exit 1; }
    mp_sql "create table qtemp.biglib (id integer not null primary key, name varchar(20))" || echo "create: $MP_ERROR"
    batch=
    for ((i = 1; i <= 5000; i++)); do batch+="${batch:+,}[$i,\"row $i\"]"; done
    mp_prepare_sql "insert into qtemp.biglib values (?, ?)" && stmt=$MP_ID || echo "prepare: $MP_ERROR"
    mp_get parameter_count; echo "parameters=$REPLY"
    mp_execute "$stmt" "[$batch]" || echo "execute: $MP_ERROR"
    mp_get update_count; echo "inserted=$REPLY"
    mp_sql "select count(*) as n, sum(id) as s from qtemp.biglib" && mp_get data.0.0 && echo "count=$REPLY" && mp_get data.0.1 && echo "sum=$REPLY"
    mp_sql "select id, name from qtemp.biglib order by id" 13 && cursor=$MP_ID || echo "select: $MP_ERROR"
    blocks=1 rows=0 next=1 sizes= errors=
    while :; do
        mp_count data; n=$REPLY
        sizes+=" $n"
        for ((r = 0; r < n; r++)); do
            mp_get "data.$r.0"; id=$REPLY; mp_get "data.$r.1"
            [[ $id == "$next" && $REPLY == "row $next" ]] || errors+=" $next"
            next=$(( next + 1 ))
        done
        rows=$(( rows + n ))
        mp_get is_done; [[ $REPLY == true ]] && break
        mp_sqlmore "$cursor" 13 || { echo "sqlmore: $MP_ERROR"; break; }
        blocks=$(( blocks + 1 ))
    done
    echo "blocks=$blocks rows=$rows errors=${errors:-none}"
    full=${sizes// 13/}; echo "short blocks:${full}"
    mp_sqlclose "$cursor" && echo closed
    mp_close
)
check "5000 rows via library, 13 at a time" $'parameters=2\ninserted=5000\ncount=5000\nsum=12502500\nblocks=385 rows=5000 errors=none\nshort blocks: 8\nclosed' "$out"

# ---------------------------------------------------------------- Parameters
check "parameter (rule A00)" $'DEPTNO\nA00\nB01\nC01\nD01\nE01' "$("${MP[@]}" -F csv --param A00 "select * from sample.department where admrdept = ?" | cut -d, -f1)"
check "parameter (rule E01)" 7 "$("${MP[@]}" -F csv --param E01 "select * from sample.department where admrdept = ?" | tail -n +2 | wc -l)"
check "parameter (no match)" "(0 rows)" "$("${MP[@]}" --param Z99 "select * from sample.department where admrdept = ?" | tail -1)"
check "parameters are strings" $'A,B,T\nA01,"x""y",text' "$("${MP[@]}" -F csv --param A01 --param 'x"y' --param 42 "select ? as A, ? as B, typeof(?) as T")"
check "raw json parameters" $'A,B,T\n1,,integer' "$("${MP[@]}" -F csv --params '[1,null,1]' "select ? as A, ? as B, typeof(?) as T")"
out=$("${MP[@]}" --param 1 "select ? as A, ? as B" 2>&1); rc=$?
check "too few parameters" 1 "$rc"
check_has "too few parameters message" "SQLSTATE 07001" "$out"

# ---------------------------------------------------------------- Statements and errors
out=$("${MP[@]}" "select * from nosuch" 2>&1); rc=$?
check "sql error exit code" 1 "$rc"
check_has "sql error message" "no such table: nosuch" "$out"
check_has "sql error state" "[SQLSTATE 42704, SQLCODE -204]" "$out"
out=$("${MP[@]}" "selec 1" 2>&1)
check_has "syntax error" "[SQLSTATE 42601, SQLCODE -104]" "$out"
out=$("${MP[@]}" "create table qtemp.c (k int)" "select nosuchcol from qtemp.c" 2>&1)
check_has "unknown column" "SQLSTATE 42703" "$out"
out=$("${MP[@]}" "create table qtemp.u (k int primary key)" "insert into qtemp.u values (1)" "insert into qtemp.u values (1)" 2>&1); rc=$?
check "duplicate key" "1|23505" "$rc|$(grep -o 23505 <<<"$out")"
out=$("${MP[@]}" "create table qtemp.n (k int not null)" "insert into qtemp.n values (null)" 2>&1)
check_has "not null" "SQLSTATE 23502" "$out"
out=$("${MP[@]}" "create table qtemp.d (k int)" "create table qtemp.d (k int)" 2>&1)
check_has "already exists" "SQLSTATE 42710" "$out"
check "update count (rule)" "1 row affected" "$("${MP[@]}" "insert into sample.department values ('X01', 'X', null, 'A00', null)")"
out=$("${MP[@]}" "create table qtemp.t (id int, name varchar(10))" "insert into qtemp.t values (1, 'a'), (2, 'b'), (3, 'c')" \
    "update qtemp.t set name = 'z' where id > 1" "delete from qtemp.t where id = 99" "select * from qtemp.t order by id" | tail -n +2)
check "DDL, DML and query in one connection" $'3 rows affected\n2 rows affected\n0 rows affected\n id | name \n----+------\n  1 | a    \n  2 | z    \n  3 | z    \n(3 rows)' "$out"
out=$("${MP[@]}" -F csv "create table qtemp.t2 (id int)" "insert into qtemp.t2 values (1)" "select * from qtemp.t2")
check "csv prints no update counts" $'id\n1' "$out"
out=$("${MP[@]}" -F json "create table qtemp.t3 (id int)" "insert into qtemp.t3 values (7)" | tail -1)
check_has "json shows update counts" '"update_count":1' "$out"
out=$("${MP[@]}" -F csv "select * from nosuch" "select 'still here' as M" 2>/dev/null); rc=$?
check "continues after an error" $'1|M\nstill here' "$rc|$out"

# ---------------------------------------------------------------- CL commands
CL_HDR=' MESSAGE_ID | TYPE       | SEVERITY | MESSAGE_TEXT'
check "cl" "$CL_HDR"$'     \n------------+------------+----------+------------------\n CPC2102    | COMPLETION |        0 | Library created. ' "$("${MP[@]}" -c "CRTLIB MYLIB")"
check "cl: default rule" $'MESSAGE_ID,TYPE,SEVERITY,MESSAGE_TEXT\nCPC0000,COMPLETION,0,Command completed by the Mapepire mock server.' "$("${MP[@]}" -F csv -c "CHGLIBL LIBL(QGPL)")"
out=$("${MP[@]}" -F csv -c "BADCMD" 2>"$TMP/err"); rc=$?
check "cl error exit code" 1 "$rc"
check "cl error shows job log" $'MESSAGE_ID,TYPE,SEVERITY,MESSAGE_TEXT\nCPD0030,DIAGNOSTIC,30,Command not found in library list.\nCPF0006,ESCAPE,30,Errors occurred in command.' "$out"
check_has "cl error message" "SQLSTATE 38501" "$(cat "$TMP/err")"
out=$("${MP[@]}" -c "DLTLIB NOSUCHLIB" 2>&1)
check_has "cl error names the escape message" "[CPF2110] Library NOSUCHLIB not found." "$out"
check "cl vertical" $'-[ RECORD 1 ]--------------------\nMESSAGE_ID   | CPC2102\nTYPE         | COMPLETION\nSEVERITY     | 0\nMESSAGE_TEXT | Library created.' "$("${MP[@]}" -F vertical -c "CRTLIB X")"
check_has "cl json" '"id":"CPC2102"' "$("${MP[@]}" -F json -c "CRTLIB X")"
check "cl after a query uses message columns" $'DEPTNO\nA00\nMESSAGE_ID\nCPC2102\nDEPTNO\nA00' \
    "$("${MP[@]}" -F csv -m 1 "select * from sample.department" -c "CRTLIB X" "select * from sample.department" | cut -d, -f1)"

# ---------------------------------------------------------------- Server requests
out=$("${MP[@]}" --ping --server-version)
check "ping + version" "alive, db_alive=true"$'\n'"server $MOCK_VERSION" "${out% (*}"
check_has "job name" "/QUSER/QZDASOINIT" "$(printf '\\job\n' | "${MP[@]}")"
out=$("${MP[@]}" --debug "select * from sysibm.sysdummy1" 2>&1 >/dev/null)
check_has "debug: request trace" '>> {"id":"2","type":"sql","sql":"select * from sysibm.sysdummy1","terse":true}' "$out"
check_has "debug: handshake trace" "<< HTTP/1.1 101" "$out"
check_has "debug: application name" '"application":"mapepire-bash"' "$out"

# ---------------------------------------------------------------- Scripts
out=$(printf 'select * from sysibm.sysdummy1;\n-- a comment\nselect\n  1 as N\n  ;\n\\job\n\nselect 2 as N' | "${MP[@]}" -F csv)
check "script from stdin" $'IBMREQD\nY\nN\n1\n'"$(grep -o '[0-9]*/QUSER/QZDASOINIT' <<<"$out")"$'\nN\n2' "$out"
printf 'create table qtemp.s (v varchar(10));\ninsert into qtemp.s values (\x27a;b\x27);\nselect v from qtemp.s;\n' >"$TMP/script.sql"
echo "select 'f' as F;" >"$TMP/one.sql"
check "script file (; inside a line is not an end)" $'v\na;b' "$("${MP[@]}" -F csv -f "$TMP/script.sql" | tail -2)"
printf 'select 1 as N;\r\nselect 2 as N;\r\n' >"$TMP/crlf.sql"
check "script with CRLF line endings" $'N\n1\nN\n2' "$("${MP[@]}" -F csv -f "$TMP/crlf.sql")"
out=$("${MP[@]}" -f "$TMP/nope.sql" 2>&1); rc=$?
check "missing script file" "1|mapepire: cannot read file: $TMP/nope.sql" "$rc|$out"
out=$(printf 'select 1 as N;\nselect * from nosuch;\nselect 3 as N;\n' | "${MP[@]}" -F csv 2>/dev/null); rc=$?
check "script continues after an error" $'1|N\n1\nN\n3' "$rc|$out"
out=$(printf '\\format csv\nselect 1 as A, 2 as B;\n\\format vertical\nselect 1 as A;\n\\rows 2\n\\cl CRTLIB X\n' | "${MP[@]}")
check "meta commands" $'A,B\n1,2\n-[ RECORD 1 ]--------------------\nA | 1\n-[ RECORD 1 ]--------------------\nMESSAGE_ID   | CPC2102\nTYPE         | COMPLETION\nSEVERITY     | 0\nMESSAGE_TEXT | Library created.' "$out"
out=$(printf '\\nope\n\\format xml\n\\rows x\n' | "${MP[@]}" 2>&1); rc=$?
check "bad meta commands" $'1|mapepire: unknown command: \\nope (try \\help)\nmapepire: format must be table, csv, vertical or json\nmapepire: \\rows needs a number' "$rc|$out"
check_has "\\help" '\cl COMMAND' "$(printf '\\help\n' | "${MP[@]}")"
check "\\quit stops the script" $'N\n1' "$(printf 'select 1 as N;\n\\quit\nselect 2 as N;\n' | "${MP[@]}" -F csv)"
check "order of SQL, -c and -f" $'A\n1\nMESSAGE_ID,TYPE,SEVERITY,MESSAGE_TEXT\nCPC2102,COMPLETION,0,Library created.\nF\nf\nB\n2' \
    "$("${MP[@]}" -F csv "select 1 as A" -c "CRTLIB X" -f "$TMP/one.sql" "select 2 as B")"

# ---------------------------------------------------------------- Library
LIB='source ./mapepire.sh; MP_HOST=127.0.0.1 MP_PORT=$PORT MP_USER=mock MP_PASSWORD=mockingbird MP_CA=$TMP/cert.pem'
out=$(
    eval "$LIB"; MP_ROWS=2
    mp_connect || { echo "connect: $MP_ERROR"; exit 1; }
    [[ $MP_JOB == */QUSER/QZDASOINIT ]] && echo "job ok"
    mp_sql "select * from sample.department" && cursor=$MP_ID && mp_get data.1.DEPTNAME && echo "row2=$REPLY"
    mp_get data.0.NOPE || echo "missing member"
    mp_get data.3.MGRNO || echo "null member"
    mp_get is_done; echo "done=$REPLY"
    mp_sqlmore "$cursor" && mp_get data.0.DEPTNO && echo "row3=$REPLY"
    mp_count data; echo "block=$REPLY"
    mp_sqlclose "$cursor" && echo closed
    mp_sqlmore "$cursor" || echo "error=$MP_ERROR"
    mp_sqlclose nosuch || echo "error=$MP_ERROR"
    mp_close; mp_connected || echo disconnected
    mp_sql "values 1" || echo "after close: $MP_ERROR"
)
check "library: objects, sqlmore, sqlclose" $'job ok\nrow2=PLANNING\nmissing member\nnull member\ndone=false\nrow3=C01\nblock=2\nclosed\nerror=invalid correlation ID\nerror=invalid correlation ID\ndisconnected\nafter close: not connected' "$out"

# The paging loop from the README: later blocks have no metadata of their own
out=$(
    eval "$LIB"
    mp_connect || exit 1
    mp_sql "select * from sample.department" 2 && cursor=$MP_ID
    mp_get is_done
    while [[ $REPLY == false ]]; do
        mp_sqlmore "$cursor" 2 || break
        mp_print_result csv
        mp_get is_done
    done
    mp_close
) ; out=$(cut -d, -f1,3 <<<"$out")
check "library: README paging loop" $'DEPTNO,MGRNO\nC01,000030\nD01,\nDEPTNO,MGRNO\nD11,000060\nD21,000070\nDEPTNO,MGRNO\nE01,000050\nE11,000090\nDEPTNO,MGRNO\nE21,000100\nF22,\nDEPTNO,MGRNO\nG22,\nH22,\nDEPTNO,MGRNO\nI22,\nJ22,' "$out"

out=$(
    eval "$LIB"; MP_TERSE=1
    mp_connect || exit 1
    mp_sql "select * from sample.department" 3 && mp_get data.2.0 && echo "terse=$REPLY"
    mp_count data.0; echo "columns=$REPLY"
    mp_print_result csv
)
check "library: terse rows" $'terse=C01\ncolumns=5\nDEPTNO,DEPTNAME,MGRNO,ADMRDEPT,LOCATION\nA00,SPIFFY COMPUTER SERVICE DIV.,000010,A00,\nB01,PLANNING,000020,A00,\nC01,INFORMATION CENTER,000030,A00,' "$out"

out=$(
    eval "$LIB"
    mp_connect || exit 1
    mp_sql "create table qtemp.p (id int, name varchar(10))"
    mp_prepare_sql "insert into qtemp.p values (?, ?)" && stmt=$MP_ID
    mp_get metadata.parameters.0.mode; echo "mode=$REPLY"
    mp_execute "$stmt" '[[1,"one"],[2,"two"]]' && mp_get batch_added && echo "batch=$REPLY"
    mp_execute "$stmt" '[3,"three"]' && mp_get update_count && echo "single=$REPLY"
    mp_prepare_sql "select * from qtemp.p" && mp_execute "$MP_ID" '[]' && mp_count data && echo "rows=$REPLY"
    mp_json_array two three
    mp_prepare_sql_execute "select id from qtemp.p where name in (?, ?) order by id" "$REPLY" && mp_print_result csv
    mp_execute "$stmt" '[[4,"x"],5]' || echo "mixed: $MP_ERROR"
    mp_execute nosuch '[1]' || echo "bad statement: $MP_ERROR"
    mp_prepare_sql "select * from qtemp.p where id = ?" && mp_execute "$MP_ID" '[[1],[2]]' || echo "batch query: $MP_ERROR"
    mp_close
)
check "library: prepare, execute, batches" $'mode=IN\nbatch=2\nsingle=1\nrows=3\nid\n2\n3\nmixed: Every entry of a batch \'parameters\' array must itself be an array\nbad statement: invalid correlation ID\nbatch query: A statement that returns a result set cannot be run as a batch.' \
    "$(sed 's/ \[SQLSTATE 07000.*\]$//' <<<"$out")"

out=$(
    eval "$LIB"
    mp_connect || exit 1
    mp_dove "select * from sample.department" && mp_count vedata && echo "nodes=$REPLY" && mp_get vedata.1.NODE_TYPE && echo "node2=$REPLY"
    mp_setconfig tracelevel=ERRORS tracedest=IN_MEM && mp_get tracelevel && echo "tracelevel=$REPLY"
    mp_setconfig bogus || echo "setconfig: $MP_ERROR"
    mp_gettracedata && echo "tracedata ok"
    mp_getdbjob && [[ $REPLY == "$MP_JOB" || -n $MP_JOB ]] && mp_get job && [[ $REPLY == "$MP_JOB" ]] && echo "same job"
    mp_getversion && mp_get version && echo "version=$REPLY"
    mp_ping && mp_get alive && echo "alive=$REPLY"
    mp_request bogus || echo "unknown: $MP_ERROR"
    mp_request getcldoc '"cmd":"CRTLIB"' || echo "missing field: $MP_ERROR"
    mp_request sqlmore || echo "no cont_id: $MP_ERROR"
    mp_close
)
check "library: other requests" "nodes=2"$'\nnode2=Table Scan\ntracelevel=ERRORS\nsetconfig: setconfig: expected key=value, got \'bogus\'\ntracedata ok\nsame job\n'"version=$MOCK_VERSION"$'\nalive=true\nunknown: Unknown request type: bogus\nmissing field: Request is missing required field \'path\'\nno cont_id: Correlation ID not specified' "$out"

out=$(
    eval "$LIB"
    mp_connect || exit 1; first=$MP_JOB
    mp_connect || exit 1; [[ $MP_JOB != "$first" ]] && echo "reconnect: new job"
    MP_PASSWORD=wrong; mp_connect || echo "bad: $MP_ERROR"; mp_connected || echo "not connected"
    MP_PASSWORD=mockingbird; mp_connect && echo "connected again"
    mp_close; mp_close && echo "double close ok"
)
check "library: reconnect and close" $'reconnect: new job\nbad: WebSocket upgrade failed: HTTP/1.1 404 WebSocket Upgrade Failure\nnot connected\nconnected again\ndouble close ok' "$out"

out=$(
    eval "$LIB"
    mp_connect || exit 1
    kill "$MP__PID"; wait "$MP__PID" 2>/dev/null
    mp_sql "values 1" || echo "lost: $MP_ERROR"
    mp_connected || echo "not connected"
)
check "library: connection lost" $'lost: connection to the server was lost\nnot connected' "$out"

# ---------------------------------------------------------------- Single mode
# The same server, started with --single: JSON over stdin/stdout, no TLS or password
SINGLE=(./mapepire.sh --single "java -jar $JAR --single")
check "single mode: query" $'IBMREQD\nY' "$("${SINGLE[@]}" -F csv "select * from sysibm.sysdummy1")"
check "single mode: table" $' IBMREQD \n---------\n Y       \n(1 row)' "$("${SINGLE[@]}" "select * from sysibm.sysdummy1")"
check "single mode: script" $'N\n1\nN\n2' "$(printf 'select 1 as N;\nselect 2 as N;\n' | "${SINGLE[@]}" -F csv)"
check "single mode: parameters" $'DEPTNO\nA00\nB01\nC01\nD01\nE01' "$("${SINGLE[@]}" -F csv --param A00 "select * from sample.department where admrdept = ?" | cut -d, -f1)"
check "single mode: cl" $'MESSAGE_ID,TYPE,SEVERITY,MESSAGE_TEXT\nCPC2102,COMPLETION,0,Library created.' "$("${SINGLE[@]}" -F csv -c "CRTLIB X")"
out=$("${SINGLE[@]}" -F csv -c "DLTLIB NOSUCHLIB" 2>&1); rc=$?
check "single mode: cl error" "1|CPF2110,ESCAPE,40,Library NOSUCHLIB not found." "$rc|$(grep ^CPF2110 <<<"$out")"
out=$("${SINGLE[@]}" "select * from nosuch" 2>&1); rc=$?
check "single mode: sql error" 1 "$rc"
check_has "single mode: sql error state" "[SQLSTATE 42704, SQLCODE -204]" "$out"
out=$("${SINGLE[@]}" --ping --server-version)
check "single mode: ping + version" "alive, db_alive=true"$'\n'"server $MOCK_VERSION" "${out% (*}"
check "single mode: unicode" $'A\ncafé 😀' "$("${SINGLE[@]}" -F csv "select 'café ' || char(128512) as A")"
out=$("${SINGLE[@]}" -F csv "select printf('%.*c', 200000, 'x') as BIG")
check "single mode: 200 KB value" 200004 "${#out}"
"${SINGLE[@]}" -F csv -r 13 "create table qtemp.big (id integer not null primary key, name varchar(20))" \
    "insert into qtemp.big $CTE select x, 'name ' || x from c" "select * from qtemp.big order by id" >"$TMP/single-big.csv"
check "single mode: 5000 rows, 13 at a time" "0|5001|5000,name 5000" "$?|$(wc -l <"$TMP/single-big.csv" | tr -d ' ')|$(tail -1 "$TMP/single-big.csv")"
out=$(./mapepire.sh --single "java -jar $TMP/no-such.jar --single" "values 1" 2>&1); rc=$?
check "single mode: server fails to start" "1|mapepire: the single-mode server exited" "$rc|$(tail -1 <<<"$out")"
out=$(
    source ./mapepire.sh
    MP_SINGLE="java -jar $JAR --single" MP_ROWS=5
    mp_connect || { echo "connect: $MP_ERROR"; exit 1; }
    [[ $MP_JOB == */QUSER/QZDASOINIT ]] && echo "job ok"
    mp_sql "select * from sample.department" && cursor=$MP_ID && mp_get data.4.DEPTNO && echo "row5=$REPLY"
    mp_sqlmore "$cursor" 100 && mp_count data && echo "rest=$REPLY"
    mp_get is_done; echo "done=$REPLY"
    mp_close; mp_connected || echo disconnected
)
check "single mode: library" $'job ok\nrow5=D11\nrest=9\ndone=true\ndisconnected' "$out"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
