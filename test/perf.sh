#!/usr/bin/env bash
# Rough timings for the JSON code on large inputs (no server needed).
cd "$(dirname "$0")/.." || exit 1
source ./mapepire.sh
ms() { echo "$(( (${2/./} - ${1/./}) / 1000 ))ms"; }
# REPLY = $1 repeated $2 times (by doubling; ${v// /x} is itself quadratic)
rep() { local r=$1 out=; local -i n=$2; while (( n )); do (( n & 1 )) && out+=$r; r+=$r; (( n >>= 1 )); done; REPLY=$out; }

for n in 20000 200000 1000000; do
    rep x "$n"; v=$REPLY
    s=$EPOCHREALTIME; mp_parse "{\"a\":\"$v\",\"b\":2}"; e=$EPOCHREALTIME; mp_get a
    echo "plain string $n: parse $(ms "$s" "$e"), get $(ms "$e" "$EPOCHREALTIME"), len ${#REPLY}, b=${MP_JSON[b]}"
done

rep 'ab\ncd\"e\\' 20000; v=$REPLY
s=$EPOCHREALTIME; mp_parse "{\"a\":\"$v\"}"; e=$EPOCHREALTIME; mp_get a
echo "escaped string (${#v} bytes, 80000 escapes): parse $(ms "$s" "$e"), get $(ms "$e" "$EPOCHREALTIME"), len ${#REPLY}"

rows=
for ((i = 0; i < 1000; i++)); do rows+="${rows:+,}[$i,\"name $i\",12.5,null,\"x\\u00e9y\"]"; done
s=$EPOCHREALTIME; mp_parse "{\"id\":\"1\",\"data\":[$rows]}"
echo "1000 rows x 5 columns (${#rows} bytes): parse $(ms "$s" "$EPOCHREALTIME"), rows=${MP_JSON[data.#]}"
