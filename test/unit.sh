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

printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
