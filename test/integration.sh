#!/usr/bin/env bash
# End-to-end tests for mapepire.sh against test/mock_server.py, over real TLS
# WebSockets and over single mode. Needs python3 and openssl (test-only).
cd "$(dirname "$0")/.." || exit 1
PY=
for py in python3 python; do
    if command -v "$py" >/dev/null && "$py" -c pass >/dev/null 2>&1; then PY=$(command -v "$py"); break; fi
done
[[ -n $PY ]] || { echo "python is required for the mock server"; exit 1; }
PORT=${MOCK_PORT:-18076}
TMP=${TMPDIR:-/tmp}/mapepire-test.$$
mkdir -p "$TMP"

MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 1 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || { echo "cannot create test cert"; exit 1; }
"$PY" test/mock_server.py --tls "$PORT" "$TMP/cert.pem" "$TMP/key.pem" >"$TMP/mock.log" 2>&1 &
MOCK=$!
trap 'kill $MOCK 2>/dev/null; rm -rf "$TMP"' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do grep -q listening "$TMP/mock.log" 2>/dev/null && break; sleep 0.5; done

MP=(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u tester -P secret --ca "$TMP/cert.pem")
SINGLE=(./mapepire.sh --single "$PY test/mock_server.py --single")
pass=0 fail=0
check() { # name expected actual
    if [[ $3 == "$2" ]]; then pass=$((pass + 1)); echo "ok   $1"
    else fail=$((fail + 1)); printf 'FAIL %s\n--- expected\n%s\n--- actual\n%s\n' "$1" "$2" "$3"; fi
}
check_has() { # name needle haystack
    if [[ $3 == *"$2"* ]]; then pass=$((pass + 1)); echo "ok   $1"
    else fail=$((fail + 1)); printf 'FAIL %s\n--- expected to contain\n%s\n--- actual\n%s\n' "$1" "$2" "$3"; fi
}

check "table" $' ID | NAME   \n----+--------\n  1 | name 1 \n  2 | name 2 \n(2 rows)' "$("${MP[@]}" "rows(2)")"

out=$("${MP[@]}" -F csv -r 1000 "rows(2500)")
IFS=$'\n' read -r -d '' -a lines <<<"$out"
check "paging: row count" 2501 "${#lines[@]}"
check "paging: last row" "2500,name 2500" "${lines[2500]}"
check "max rows csv" $'ID,NAME\n1,name 1\n2,name 2\n3,name 3' "$("${MP[@]}" -F csv -r 2 -m 3 "rows(10)")"
check_has "max rows table" "(5 rows)" "$("${MP[@]}" -m 5 "rows(2500)")"

out=$("${MP[@]}" -F csv big)
check "64-bit frame length" 200004 "${#out}"
check "fragmented message" $'SQL\nfrag' "$("${MP[@]}" -F csv frag)"
check "unicode + escapes" $'A,B,C,D,E\ncafé <b>&amp;</b> \'q\' a=b,😀,"tab\there\nnewline",,"quote "" \\ /"' "$("${MP[@]}" -F csv unicode)"
check "vertical" $'-[ RECORD 1 ]--------------------\nID   | 1\nNAME | name 1' "$("${MP[@]}" -F vertical "rows(1)")"
out=$("${MP[@]}" -F json "rows(1)")
check_has "json" '"data":[[1,"name 1"]]' "$out"

out=$("${MP[@]}" "select * from FAIL" 2>&1); rc=$?
check "sql error exit code" 1 "$rc"
check_has "sql error message" "[SQLSTATE 42704, SQLCODE -204]" "$out"
check "update count" "3 rows affected" "$("${MP[@]}" "insert into t values(1)")"

out=$("${MP[@]}" --ping --server-version)
check "ping + version" $'alive, db_alive=true\nserver 9.9.9-mock (2026-01-01)' "$out"
check_has "answered server ping (NUL in payload)" "got pong b'\\x00hello\\xff'" "$(cat "$TMP/mock.log")"

check "cl" $' MESSAGE_ID | SEVERITY | MESSAGE_TEXT          \n------------+----------+-----------------------\n CPC2101    |        0 | Library list changed. ' "$("${MP[@]}" -c "CHGLIBL LIBL(QGPL)")"
out=$("${MP[@]}" -c "ADDLIBLE BAD" 2>&1); rc=$?
check "cl error exit code" 1 "$rc"
check_has "cl error shows job log" "CPF2110    |       40 | Library BAD not found." "$out"

check "parameters" $'PARAMS\n"[""A01"", ""x\\""y""]"' "$("${MP[@]}" -F csv --param A01 --param 'x"y' "select ?")"
check "raw json parameters" $'PARAMS\n"[1, null]"' "$("${MP[@]}" -F csv --params '[1,null]' "select ?")"

out=$(printf 'rows(1);\n-- a comment\nselect\n  2;\n\\job\nlast statement' | "${MP[@]}" -F csv)
check "script from stdin" $'ID,NAME\n1,name 1\nSQL\n"select\n  2"\n123456/QUSER/QZDASOINIT\nSQL\nlast statement' "$out"

out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u tester -P wrong --ca "$TMP/cert.pem" "values 1" 2>&1); rc=$?
check "bad password" "1|mapepire: authentication failed for user tester (HTTP/1.1 401 Unauthorized)" "$rc|$out"
out=$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u tester -P secret "values 1" 2>&1); rc=$?
check "untrusted cert rejected" 1 "$rc"
check_has "untrusted cert hint" "--print-cert" "$out"
check "insecure (-k) accepted" $'SQL\nvalues 1' "$(./mapepire.sh -H 127.0.0.1 -p "$PORT" -u tester -P secret -k -F csv "values 1")"
out=$(./mapepire.sh -H 127.0.0.1 -p 1 -u tester -P secret -k "values 1" 2>&1); rc=$?
check "connection refused" 1 "$rc"
check_has "connection refused message" "TLS connection to 127.0.0.1:1 failed" "$out"
check "print cert" "$(cat "$TMP/cert.pem")" "$(./mapepire.sh -H 127.0.0.1 -p "$PORT" --print-cert)"

check "single mode" $'ID,NAME\n1,name 1\n2,name 2' "$("${SINGLE[@]}" -F csv "rows(2)")"
check "single mode script" $'SQL\na\nSQL\nb' "$(printf 'a;\nb;\n' | "${SINGLE[@]}" -F csv)"

# Library use
out=$(
    source ./mapepire.sh
    MP_HOST=127.0.0.1 MP_PORT=$PORT MP_USER=tester MP_PASSWORD=secret MP_CA=$TMP/cert.pem MP_ROWS=2
    mp_connect || { echo "connect: $MP_ERROR"; exit 1; }
    echo "job=$MP_JOB"
    mp_sql "rows(3)" && cursor=$MP_ID && mp_get data.1.NAME && echo "row2=$REPLY"
    mp_get is_done; echo "done=$REPLY"
    mp_sqlmore "$cursor" && mp_get data.0.ID && echo "row3=$REPLY"
    mp_sqlclose "$cursor" && echo closed
    mp_sqlmore "$cursor" || echo "error=$MP_ERROR"
    mp_close; mp_connected || echo disconnected
)
check "library" $'job=123456/QUSER/QZDASOINIT\nrow2=name 2\ndone=false\nrow3=3\nclosed\nerror=invalid correlation ID\ndisconnected' "$out"

# The paging loop from the README: later blocks have no metadata of their own
out=$(
    source ./mapepire.sh
    MP_HOST=127.0.0.1 MP_PORT=$PORT MP_USER=tester MP_PASSWORD=secret MP_CA=$TMP/cert.pem
    mp_connect || exit 1
    mp_sql "rows(5)" 2 && cursor=$MP_ID
    mp_get is_done
    while [[ $REPLY == false ]]; do
        mp_sqlmore "$cursor" 2 || break
        mp_print_result csv
        mp_get is_done
    done
    mp_close
)
check "library paging + mp_print_result" $'ID,NAME\n3,name 3\n4,name 4\nID,NAME\n5,name 5' "$out"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
