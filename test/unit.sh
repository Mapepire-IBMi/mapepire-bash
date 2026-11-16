#!/usr/bin/env bash
# Unit tests for the pure bash primitives in mapepire.sh (no server needed).
cd "$(dirname "$0")/.." || exit 1
source ./mapepire.sh

pass=0 fail=0
check() { # name expected actual
    if [[ $2 == "$3" ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); printf 'FAIL %s\n  expected: %q\n  actual:   %q\n' "$1" "$2" "$3"; fi
}

# Base64
for pair in ":" "f:Zg==" "fo:Zm8=" "foo:Zm9v" "foobar:Zm9vYmFy" "user:pass:dXNlcjpwYXNz"; do
    mp__str_bytes "${pair%:*}"; mp__b64; check "b64 ${pair%:*}" "${pair##*:}" "$REPLY"
done

# SHA-1 / RFC 6455 accept key
hex() { local h= b; for b in "${MP__BYTES[@]}"; do printf -v b '%02x' "$b"; h+=$b; done; REPLY=$h; }
mp__str_bytes "abc"; mp__sha1; hex; check "sha1 abc" a9993e364706816aba3e25717850c26c9cd0d89d "$REPLY"
mp__str_bytes ""; mp__sha1; hex; check "sha1 empty" da39a3ee5e6b4b0d3255bfef95601890afd80709 "$REPLY"
mp__str_bytes "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"; mp__sha1; hex
check "sha1 2-block" 84983e441c3bd26ebaae4aa1f95129e5e54670f1 "$REPLY"
mp__str_bytes "dGhlIHNhbXBsZSBub25jZQ==$MP__WS_GUID"; mp__sha1; mp__b64
check "ws accept" "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" "$REPLY"

# JSON encoding
mp_json_str 'plain'; check "str plain" '"plain"' "$REPLY"
mp_json_str 'a"b\c'; check "str quote" '"a\"b\\c"' "$REPLY"
mp_json_str $'l1\nl2\tx\r'; check "str ctl" '"l1\nl2\tx\r"' "$REPLY"
mp_json_str $'bell\x07'; check "str other ctl" '"bell\u0007"' "$REPLY"
mp_json_str 'café & <tag>'; check "str utf8" '"café & <tag>"' "$REPLY"
mp_json_array a 'b"' ''; check "array" '["a","b\"",""]' "$REPLY"

# JSON decoding
mp__unescape '"a\"b\\c\/d\n"'; check "unescape" $'a"b\\c/d\n' "$REPLY"
mp__unescape '"<b> & é €"'; check "unescape \\u" '<b> & é €' "$REPLY"
mp__unescape '"😀!"'; check "unescape surrogate" '😀!' "$REPLY"

json='{"id":"7","success":true,"n":-1.5e3,"x":null,"s":"q\"}[,","e":[],"o":{},
  "data":[["000010","HAAS",null],["a\\b",2,true]],
  "metadata":{"columns":[{"name":"EMPNO","type":"CHAR"},{"name":"A B","type":"INTEGER"}]}}'
mp_parse "$json"; check "parse ok" 0 $?
check "parse id" '"7"' "${MP_JSON[id]}"
check "parse bool" true "${MP_JSON[success]}"
check "parse num" -1.5e3 "${MP_JSON[n]}"
check "parse null" null "${MP_JSON[x]}"
check "parse tricky str" '"q\"}[,"' "${MP_JSON[s]}"
check "parse empty arr" 0 "${MP_JSON[e.#]}"
check "parse rows" 2 "${MP_JSON[data.#]}"
check "parse cols" 3 "${MP_JSON[data.0.#]}"
check "parse cell" '"HAAS"' "${MP_JSON[data.0.1]}"
check "parse nested" '"A B"' "${MP_JSON[metadata.columns.1.name]}"
mp_get data.1.0; check "get decoded" 'a\b' "$REPLY"
mp_get data.0.2; check "get null status" 1 $?
mp_get nope; check "get missing status" 1 $?
mp_count metadata.columns; check "count" 2 "$REPLY"
mp_parse '{"a":'; check "parse truncated fails" 1 $?
mp_parse '{"a":tru}'; check "parse bad literal fails" 1 $?

# Backslashes next to quotes: \\" ends a string, \" and \\\" do not
mp_parse '{"a":"x\\","b":"y\\\"z\"","c":"\\\\","d":["\"",",:[{"]}'
check "parse bs-quote ok" 0 $?
mp_get a; check "escaped bs before end quote" 'x\' "$REPLY"
mp_get b; check "bs + escaped quote" 'y\"z"' "$REPLY"
mp_get c; check "only backslashes" '\\' "$REPLY"
mp_get d.0; check "lone escaped quote" '"' "$REPLY"
mp_get d.1; check "structural chars in string" ',:[{' "$REPLY"
mp__unescape_body 'tail\\'; check "unescape trailing bs" 'tail\' "$REPLY"
mp__unescape_body 'é\\\n\\u0041'; check "unescape mixed" $'é\\\n\\u0041' "$REPLY"
mp_parse '{"a":"unterminated\"}'; check "parse escaped end quote fails" 1 $?

# Long strings
printf -v long '%*s' 5000 ''; long=${long// /x}
mp_parse "{\"a\":\"$long\\\"$long\",\"b\":1}"
mp_get a; check "parse long str" "$long\"$long" "$REPLY"
check "parse after long" 1 "${MP_JSON[b]}"

# Rendering
mp_parse "$json"; mp__columns metadata
check "columns" "EMPNO|A B" "$(IFS='|'; echo "${MP_COLS[*]}")"
check "numcols" "0 1" "${MP_NUMCOLS[*]}"
mp_parse '{"metadata":{"columns":[{"name":"K","type":"CHAR"},{"name":"V","type":"VARCHAR"}]},"data":[["1","x,y"],["2",null],["3","say \"hi\""]]}'
mp__columns metadata   # mp_request does this for every response with metadata
check "csv" $'K,V\n1,"x,y"\n2,\n3,"say ""hi"""' "$(mp_print_result csv)"
check "table" $' K | V        \n---+----------\n 1 | x,y      \n 2 | NULL     \n 3 | say "hi" ' "$(mp_print_result table)"
check "vertical" $'-[ RECORD 1 ]--------------------\nK | 1\nV | x,y\n-[ RECORD 2 ]--------------------\nK | 2\nV | NULL\n-[ RECORD 3 ]--------------------\nK | 3\nV | say "hi"' "$(mp_print_result vertical)"
mp_parse '{"metadata":{"columns":[{"name":"T","type":"VARCHAR"}]},"data":[["a\tb\nc"]]}'; mp__columns metadata
check "table flattens tabs/newlines" $' T     \n-------\n a b c ' "$(mp_print_result table)"
check "csv keeps newlines" $'T\n"a\tb\nc"' "$(mp_print_result csv)"
mp_parse '{"metadata":{"columns":[{"name":"N","type":"DECIMAL"},{"name":"S","type":"CHAR"}]},"data":[{"N":1.5,"S":"a"},{"N":-12,"S":null}]}'; mp__columns metadata
check "object rows, numbers right-aligned" $' N   | S    \n-----+------\n 1.5 | a    \n -12 | NULL ' "$(mp_print_result table)"
mp_parse '{"metadata":{"columns":[{"label":"ONLY_LABEL","type":"INTEGER"}]},"data":[[1]]}'; mp__columns metadata
check "label when no name" ONLY_LABEL "${MP_COLS[0]}"

# ---------------------------------------------------------------- WebSocket frames
# The server side of these cases (fragmentation, pings, close frames, masked frames)
# is not something the mock server produces on demand, so they are fed in as bytes.
TMP=${TMPDIR:-/tmp}/mapepire-unit.$$
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
# REPLY = $1 repeated $2 times (by doubling)
rep() { local r=$1 out=; local -i n=$2; while (( n )); do (( n & 1 )) && out+=$r; r+=$r; (( n >>= 1 )); done; REPLY=$out; }
# REPLY = printf escapes for a server frame: FIN+opcode byte $1, payload $2 (raw bytes)
srv_frame() {
    local LC_ALL=C p=$2 h
    local -i n=${#2} i
    printf -v h '\\x%02x' "$1"
    if (( n < 126 )); then printf -v i '%d' "$n"; h+=${MP__HEX[i]}
    elif (( n < 65536 )); then h+=${MP__HEX[126]}${MP__HEX[n >> 8]}${MP__HEX[n & 255]}
    else h+=${MP__HEX[127]}; for ((i = 56; i >= 0; i -= 8)); do h+=${MP__HEX[n >> i & 255]}; done
    fi
    p=${p//\\/\\\\}; p=${p//%/%%}
    REPLY=$h$p
}
# Start a fake transport: the client reads the bytes of printf format $1 and writes to $TMP/out
ws_feed() {
    printf "$1" >"$TMP/in"; : >"$TMP/out"
    exec {MP__IN}<"$TMP/in" {MP__OUT}>"$TMP/out"
    MP__KIND=tls MP__PID=
}
ws_done() { mp__close_transport; }
# Decode the frames the client wrote into F_OP[], F_MASKED[], F_LEN[], F_LENCODE[] (7-bit length field), F_KEY[], F_PAYLOAD[] (unmasked, as decimal bytes)
ws_sent() {
    local fd k pl
    local -i b0 b1 len i
    local -a key
    F_OP=() F_MASKED=() F_LEN=() F_LENCODE=() F_KEY=() F_PAYLOAD=()
    exec {fd}<"$TMP/out"
    local MP__IN=$fd
    while mp__getc; do
        b0=$REPLY; mp__getc; b1=$REPLY
        len=$(( b1 & 127 ))
        if (( len == 126 )); then mp__getc; len=$(( REPLY << 8 )); mp__getc; len+=REPLY
        elif (( len == 127 )); then len=0; for ((i = 0; i < 8; i++)); do mp__getc; len=$(( len << 8 | REPLY )); done
        fi
        key=()
        if (( b1 & 128 )); then for ((i = 0; i < 4; i++)); do mp__getc; key+=("$REPLY"); done; else key=(0 0 0 0); fi
        pl=
        for ((i = 0; i < len; i++)); do mp__getc; pl+="$(( REPLY ^ key[i & 3] )) "; done
        F_OP+=($(( b0 ))) F_MASKED+=($(( b1 >> 7 ))) F_LEN+=("$len") F_LENCODE+=($(( b1 & 127 ))) F_KEY+=("${key[*]}") F_PAYLOAD+=("${pl% }")
    done
    exec {fd}<&-
}

srv_frame 0x81 '{"id":"1"}'; ws_feed "$REPLY"
mp__ws_recv; check "ws recv small" '0|{"id":"1"}' "$?|$MP__MSG"; ws_done
rep 'abcdefghij' 30; body=$REPLY
srv_frame 0x81 "$body"; ws_feed "$REPLY"
mp__ws_recv; check "ws recv 16-bit length" "0|300" "$?|${#MP__MSG}"; check "ws recv 16-bit content" "$body" "$MP__MSG"; ws_done
rep 'z' 70000; body=$REPLY
srv_frame 0x81 "$body"; ws_feed "$REPLY"
mp__ws_recv; check "ws recv 64-bit length" "0|70000" "$?|${#MP__MSG}"; ws_done
srv_frame 0x81 'café 😀 \n %s'; ws_feed "$REPLY"
mp__ws_recv; check "ws recv utf-8 (length in bytes)" 'café 😀 \n %s' "$MP__MSG"; ws_done
srv_frame 0x81 ''; ws_feed "$REPLY"
mp__ws_recv; check "ws recv empty message" "0|" "$?|$MP__MSG"; ws_done

# Fragmented message with a ping (binary payload with NUL and 0xFF) between fragments
srv_frame 0x01 '{"id":'; f=$REPLY
f+='\x89\x07\x00hello\xff'
srv_frame 0x00 '"2","x"'; f+=$REPLY
srv_frame 0x80 ':true}'; f+=$REPLY
srv_frame 0x81 'next'; f+=$REPLY
ws_feed "$f"
mp__ws_recv; check "ws fragmented message" '0|{"id":"2","x":true}' "$?|$MP__MSG"
mp__ws_recv; check "ws message after fragments" 'next' "$MP__MSG"
ws_done; ws_sent
check "ws ping answered with one pong" "1|138|1|7" "${#F_OP[@]}|${F_OP[0]}|${F_MASKED[0]}|${F_LEN[0]}"
check "ws pong echoes ping payload" "0 104 101 108 108 111 255" "${F_PAYLOAD[0]}"
ws_feed '\x89\x00\x81\x02ok'
mp__ws_recv; check "ws empty ping" "0|ok" "$?|$MP__MSG"; ws_done; ws_sent
check "ws empty pong" "138|0" "${F_OP[0]}|${F_LEN[0]}"
ws_feed '\x8a\x03abc\x81\x02ok'
mp__ws_recv; check "ws unsolicited pong ignored" "0|ok|0" "$?|$MP__MSG|$(wc -c <"$TMP/out")"; ws_done

# Close frames
ws_feed '\x88\x05\x03\xe8bye'
mp__ws_recv; rc=$?
check "ws close: status" 1 "$rc"
check "ws close: error" "server closed the connection (code 1000: bye)" "$MP_ERROR"
check "ws close: transport closed" "" "$MP__KIND"
ws_sent; check "ws close: echoed with status" "1|136|1|3 232" "${#F_OP[@]}|${F_OP[0]}|${F_MASKED[0]}|${F_PAYLOAD[0]}"
ws_feed '\x88\x00'
mp__ws_recv; check "ws close without status" "1|server closed the connection (code 0)" "$?|$MP_ERROR"
ws_feed '\x88\x02\x03\xf3'
mp__ws_recv; check "ws close 1011" "server closed the connection (code 1011)" "$MP_ERROR"

# The peer is already gone (broken pipe): SIGPIPE must not kill the script
out=$(
    ws_feed '\x88\x02\x03\xe8'
    exec {MP__OUT}>&- {MP__OUT}> >(:)
    sleep 0.5
    mp__ws_recv; echo "survived: $MP_ERROR"
)
check "ws close echo to a broken pipe" "survived: server closed the connection (code 1000)" "$out"
out=$(
    ws_feed ''
    exec {MP__OUT}>&- {MP__OUT}> >(:)
    sleep 30 & MP__PID=$!
    sleep 0.5
    mp_close; echo "survived: rc=$? kind=$MP__KIND"
)
check "mp_close with a broken pipe" "survived: rc=0 kind=" "$out"

# Malformed input
ws_feed '\x81\x82abcd\x00\x00'
mp__ws_recv; check "ws masked server frame rejected" "1|protocol error: server sent a masked frame|" "$?|$MP_ERROR|$MP__KIND"
ws_feed '\x81\x0aonly4'
mp__ws_recv; check "ws truncated payload" 1 $?; ws_done
ws_feed '\x81'
mp__ws_recv; check "ws truncated header" 1 $?; ws_done
ws_feed '\x81\x7e\x01'
mp__ws_recv; check "ws truncated 16-bit length" 1 $?; ws_done
ws_feed ''
mp__ws_recv; check "ws eof" 1 $?; ws_done

# Client frames are masked, FIN set, with the right length encoding
for spec in 0:0 5:5 125:125 126:126 65535:126 65536:127; do
    n=${spec%:*}
    rep 'q' "$n"; body=$REPLY
    ws_feed ''
    mp__str_bytes "$body"; mp__ws_frame 1; ws_done; ws_sent
    want=; (( n > 0 )) && { rep '113 ' "$n"; want=${REPLY% }; }
    check "ws send $n bytes" "1|129|1|$n|${spec#*:}|1" \
        "${#F_OP[@]}|${F_OP[0]}|${F_MASKED[0]}|${F_LEN[0]}|${F_LENCODE[0]}|$([[ ${F_PAYLOAD[0]} == "$want" ]] && echo 1)"
done
ws_feed ''; mp__str_bytes 'é😀'; mp__ws_frame 1; ws_done; ws_sent
check "ws send utf-8 bytes" "6|195 169 240 159 152 128" "${F_LEN[0]}|${F_PAYLOAD[0]}"
ws_feed ''; MP__BYTES=(3 232); mp__ws_frame 8; ws_done; ws_sent
check "ws send close" "136|3 232" "${F_OP[0]}|${F_PAYLOAD[0]}"
# Two frames of the same payload use different masking keys
ws_feed ''; mp__str_bytes 'same payload'; mp__ws_frame 1; mp__str_bytes 'same payload'; mp__ws_frame 1; ws_done; ws_sent
check "ws masking keys differ" "2|1" "${#F_OP[@]}|$([[ ${F_KEY[0]} != "${F_KEY[1]}" && ${F_PAYLOAD[0]} == "${F_PAYLOAD[1]}" ]] && echo 1)"

# Request/response through the single-mode transport, with a fake server
cat >"$TMP/fake.sh" <<'EOF'
echo "fake single server starting"   # not JSON: the client must skip it
while IFS= read -r line; do
    id=${line#*\"id\":\"}; id=${id%%\"*}
    case $line in
        *'"type":"connect"'*) echo "{\"id\":\"$id\",\"job\":\"1/FAKE/JOB\",\"success\":true}" ;;
        *'"type":"cl"'*) echo '{"id":"stale","success":true}'
                         echo "{\"id\":\"$id\",\"data\":[{\"id\":\"CPF9801\",\"type\":\"ESCAPE\",\"severity\":40,\"text\":\"Object not found.\"}],\"success\":false,\"error\":\"CL failed\",\"sql_state\":\"38501\",\"sql_rc\":-443}" ;;
        *'"type":"exit"'*) echo "{\"id\":\"$id\",\"success\":true}"; exit ;;
        *) echo "{\"id\":\"$id\",\"has_results\":true,\"metadata\":{\"columns\":[{\"name\":\"X\",\"type\":\"INTEGER\"}]},\"data\":[[42]],\"is_done\":true,\"success\":true}" ;;
    esac
done
EOF
out=$(
    MP_SINGLE="bash $TMP/fake.sh"
    mp_connect || { echo "connect: $MP_ERROR"; exit; }
    echo "job=$MP_JOB"
    mp_sql "values 42" && mp_print_result csv
    mp_cl "DLTOBJ X" || echo "error=$MP_ERROR"
    mp_print_result csv
    mp_close; mp_connected || echo closed
    mp_sql x || echo "after close: $MP_ERROR"
)
check "single mode: fake server, stale messages skipped, cl job log" $'job=1/FAKE/JOB\nX\n42\nerror=CL failed [SQLSTATE 38501, SQLCODE -443]\nMESSAGE_ID,TYPE,SEVERITY,MESSAGE_TEXT\nCPF9801,ESCAPE,40,Object not found.\nclosed\nafter close: not connected' "$out"
out=$(MP_SINGLE="true"; mp_connect || echo "$MP_ERROR")
check "single mode: server exits at once" "the single-mode server exited" "$out"

printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
